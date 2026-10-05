package main

import (
	"context"
	"errors"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type historyReader interface {
	GetJobByName(context.Context, string) (store.JobRecord, error)
	ListJobScans(context.Context, string, int) ([]model.Scan, error)
	ListJobEvents(context.Context, string, int) ([]model.Event, error)
	ListScans(context.Context, string, int) ([]model.Scan, error)
	ListEvents(context.Context, string, int) ([]model.Event, error)
}

// listHistory keeps managed history attached to a stable job ID while
// preserving name-based lookup for legacy YAML jobs that have no job record.
func listHistory(ctx context.Context, reader historyReader, jobName string, limit int) ([]model.Scan, []model.Event, error) {
	if jobName != "" {
		record, lookupErr := reader.GetJobByName(ctx, jobName)
		switch {
		case lookupErr == nil:
			scans, err := reader.ListJobScans(ctx, record.ID, limit)
			if err != nil {
				return nil, nil, err
			}
			events, err := reader.ListJobEvents(ctx, record.ID, limit)
			if err != nil {
				return nil, nil, err
			}
			return scans, events, nil
		case errors.Is(lookupErr, store.ErrNotFound):
			scans, err := reader.ListScans(ctx, jobName, limit)
			if err != nil {
				return nil, nil, err
			}
			events, err := reader.ListEvents(ctx, jobName, limit)
			if err != nil {
				return nil, nil, err
			}
			return scans, events, nil
		default:
			return nil, nil, lookupErr
		}
	}
	scans, err := reader.ListScans(ctx, "", limit)
	if err != nil {
		return nil, nil, err
	}
	events, err := reader.ListEvents(ctx, "", limit)
	if err != nil {
		return nil, nil, err
	}
	return scans, events, nil
}
