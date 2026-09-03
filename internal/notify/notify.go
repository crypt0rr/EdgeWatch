package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/containrrr/shoutrrr"
	"github.com/containrrr/shoutrrr/pkg/types"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type Notifier struct {
	Store *store.Store
	URLs  map[string]string
}

func New(s *store.Store, urls []string) (*Notifier, error) {
	n := &Notifier{Store: s, URLs: map[string]string{}}
	for _, url := range urls {
		if _, err := shoutrrr.CreateSender(url); err != nil {
			id := hashURL(url)
			return nil, fmt.Errorf("invalid Shoutrrr destination %s", id[:12])
		}
		n.URLs[hashURL(url)] = url
	}
	return n, nil
}
func hashURL(url string) string { h := sha256.Sum256([]byte(url)); return hex.EncodeToString(h[:]) }

func (n *Notifier) Queue(ctx context.Context, events []model.Event) error {
	for _, event := range events {
		for destination := range n.URLs {
			if err := n.Store.QueueEvent(ctx, destination, event); err != nil {
				return err
			}
		}
	}
	return nil
}
func (n *Notifier) Drain(ctx context.Context) error {
	deliveries, err := n.Store.DueDeliveries(ctx, 100)
	if err != nil {
		return err
	}
	var all []error
	for _, d := range deliveries {
		url, ok := n.URLs[d.Destination]
		var sendErr error
		if !ok {
			sendErr = errors.New("notification destination is no longer configured")
		} else {
			sendErr = send(url, engine.FormatEvent(d.Event))
		}
		if err := n.Store.DeliveryResult(ctx, d.ID, sendErr); err != nil {
			all = append(all, err)
		}
		if sendErr != nil {
			all = append(all, sendErr)
		}
	}
	return errors.Join(all...)
}
func send(url, message string) error {
	sender, err := shoutrrr.CreateSender(url)
	if err != nil {
		return err
	}
	sender.Timeout = 15 * time.Second
	errs := sender.Send(message, &types.Params{"title": "EdgeWatch"})
	return errors.Join(errs...)
}
func (n *Notifier) Test() error {
	var errs []error
	for _, url := range n.URLs {
		if err := send(url, "EdgeWatch notification test"); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
