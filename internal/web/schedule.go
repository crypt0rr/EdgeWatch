package web

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// scheduleSuggestionResponse describes a possible 30-minute offset for a new
// job. Suggestions are advisory: the caller may keep the requested schedule
// when overlapping runs are intentional.
type scheduleSuggestionResponse struct {
	Suggested         bool               `json:"suggested"`
	SuggestedSchedule string             `json:"suggested_schedule,omitempty"`
	OffsetMinutes     int                `json:"offset_minutes,omitempty"`
	Nearest           *scheduleReference `json:"nearest,omitempty"`
	DraftNextRun      string             `json:"draft_next_run,omitempty"`
	GapMinutes        int                `json:"gap_minutes"`
}

type scheduleReference struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Schedule string `json:"schedule"`
	Timezone string `json:"timezone"`
	NextRun  string `json:"next_run"`
}

// scheduleSuggestion compares the next run of a proposed schedule with the
// next run of every active, non-archived managed job. The endpoint intentionally
// has no mutation side effects and does not include job definitions beyond the
// schedule metadata needed by the editor.
func (s *Server) scheduleSuggestion(w http.ResponseWriter, r *http.Request) {
	schedule := strings.TrimSpace(r.URL.Query().Get("schedule"))
	timezone := strings.TrimSpace(r.URL.Query().Get("timezone"))
	if schedule == "" {
		writeError(w, http.StatusBadRequest, "invalid_schedule", "schedule is required", map[string]string{"schedule": "schedule is required"})
		return
	}
	if timezone == "" {
		writeError(w, http.StatusBadRequest, "invalid_timezone", "timezone is required", map[string]string{"timezone": "timezone is required"})
		return
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		message := "invalid timezone: " + err.Error()
		writeError(w, http.StatusBadRequest, "invalid_timezone", message, map[string]string{"timezone": message})
		return
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	now := time.Now().UTC()
	draft, err := parseNextRun(parser, schedule, timezone, now)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_schedule", err.Error(), map[string]string{"schedule": err.Error()})
		return
	}

	jobs, err := s.Store.ListJobs(r.Context(), false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	var nearest *scheduleReference
	var nearestRun time.Time
	nearestDistance := time.Duration(math.MaxInt64)
	for _, record := range jobs {
		if record.Archived || !record.Enabled {
			continue
		}
		next, nextErr := parseNextRun(parser, record.Job.Schedule, record.Job.Timezone, now)
		if nextErr != nil {
			// Managed jobs are validated before persistence. Skip a malformed
			// legacy row rather than making the new-job editor unusable.
			continue
		}
		distance := next.Sub(draft)
		if distance < 0 {
			distance = -distance
		}
		if nearest == nil || distance < nearestDistance || (distance == nearestDistance && record.ID < nearest.ID) {
			nearestDistance = distance
			nearestRun = next
			nearest = &scheduleReference{ID: record.ID, Name: record.Job.Name, Schedule: record.Job.Schedule, Timezone: record.Job.Timezone, NextRun: next.Format(time.RFC3339)}
		}
	}

	response := scheduleSuggestionResponse{Nearest: nearest, DraftNextRun: draft.Format(time.RFC3339), GapMinutes: 0}
	if nearest == nil {
		writeJSON(w, http.StatusOK, response)
		return
	}
	response.GapMinutes = int(nearestDistance / time.Minute)
	if nearestDistance >= 30*time.Minute {
		writeJSON(w, http.StatusOK, response)
		return
	}

	response.Suggested = true
	// Move away from the neighbor: a draft that is already later should move
	// later still, while a draft before the neighbor should move earlier.
	response.OffsetMinutes = 30
	if draft.Before(nearestRun) {
		response.OffsetMinutes = -30
	}
	if shifted, ok := shiftCronMinute(schedule, response.OffsetMinutes); ok {
		if shiftedNext, nextErr := parseNextRun(parser, shifted, timezone, now); nextErr == nil {
			shiftedDistance := shiftedNext.Sub(nearestRun)
			if shiftedDistance < 0 {
				shiftedDistance = -shiftedDistance
			}
			if shiftedDistance > nearestDistance {
				response.SuggestedSchedule = shifted
			} else {
				response.Suggested = false
				response.OffsetMinutes = 0
			}
		} else {
			response.Suggested = false
			response.OffsetMinutes = 0
		}
	} else {
		response.Suggested = false
		response.OffsetMinutes = 0
	}
	writeJSON(w, http.StatusOK, response)
}

func parseNextRun(parser cron.Parser, schedule, timezone string, now time.Time) (time.Time, error) {
	if strings.HasPrefix(schedule, "TZ=") || strings.HasPrefix(schedule, "CRON_TZ=") {
		return time.Time{}, errors.New("schedule must contain five cron fields; set timezone in the timezone field")
	}
	location, err := time.LoadLocation(strings.TrimSpace(timezone))
	if err != nil {
		return time.Time{}, errors.New("invalid timezone: " + err.Error())
	}
	parsed, err := parser.Parse(strings.TrimSpace(schedule))
	if err != nil {
		return time.Time{}, errors.New("invalid schedule: " + err.Error())
	}
	next := parsed.Next(now.In(location))
	if next.IsZero() {
		return time.Time{}, errors.New("schedule never fires")
	}
	return next.UTC(), nil
}

// shiftCronMinute returns a safe five-field cron expression when its minute
// field is a single integer. Expressions such as */15 or 0,30 are left alone
// because rewriting them would change more than the requested 30-minute offset.
// When the minute wraps, a numeric hour is carried as well. Day-boundary
// carries are only allowed for an unrestricted daily expression; otherwise a
// suggestion could silently move a run onto the wrong calendar day.
func shiftCronMinute(schedule string, offset int) (string, bool) {
	fields := strings.Fields(schedule)
	if len(fields) != 5 || offset == 0 {
		return "", false
	}
	minute, err := strconv.Atoi(fields[0])
	if err != nil || minute < 0 || minute > 59 {
		return "", false
	}
	hour, hourErr := strconv.Atoi(fields[1])
	if hourErr == nil && (hour < 0 || hour > 23) {
		hourErr = errors.New("hour out of range")
	}
	if hourErr == nil {
		total := hour*60 + minute + offset
		dayDelta := total / (24 * 60)
		if total < 0 && total%(24*60) != 0 {
			dayDelta--
		}
		total = ((total % (24 * 60)) + (24 * 60)) % (24 * 60)
		if dayDelta != 0 && (fields[2] != "*" || fields[3] != "*" || fields[4] != "*") {
			return "", false
		}
		fields[0] = strconv.Itoa(total % 60)
		fields[1] = strconv.Itoa(total / 60)
		return strings.Join(fields, " "), true
	}
	minute += offset
	if minute < 0 || minute > 59 {
		return "", false
	}
	fields[0] = strconv.Itoa(minute)
	return strings.Join(fields, " "), true
}
