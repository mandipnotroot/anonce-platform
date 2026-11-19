// SPDX-License-Identifier: AGPL-3.0-only
package protocol

import (
	"fmt"
	"strconv"
)

const (
	MaxDescriptorBytes    = 786432
	PendingPaddingBytes   = 1048576
	MaxResponseBytes      = 524288
	AnonymousRequestBytes = 1048576
	MaxQuestionLabelBytes = 2000
	MaxChoices            = 100
	MaxChoiceLabelBytes   = 1000
)

// Limits are deployment policy bounded by the protocol's hard ceilings.
type Limits struct {
	MaxQuestions        int `json:"max_questions"`
	MaxReviewBytes      int `json:"max_review_bytes"`
	MaxDescriptionBytes int `json:"max_description_bytes"`
	MaxResponseBytes    int `json:"max_response_bytes"`
}

func Defaults() Limits { return Limits{500, 524288, 65536, MaxResponseBytes} }

// Effective interprets only the entirely zero value as defaults.
func (l Limits) Effective() Limits {
	if l == (Limits{}) {
		return Defaults()
	}
	return l
}

func (l Limits) Validate() error {
	d := Defaults()
	for _, v := range []struct {
		name            string
		value, min, max int
	}{
		{"max_questions", l.MaxQuestions, 1, d.MaxQuestions},
		{"max_review_bytes", l.MaxReviewBytes, 1024, d.MaxReviewBytes},
		{"max_description_bytes", l.MaxDescriptionBytes, 1, d.MaxDescriptionBytes},
		{"max_response_bytes", l.MaxResponseBytes, 1024, d.MaxResponseBytes},
	} {
		if v.value < v.min || v.value > v.max {
			return fmt.Errorf("%s must be between %d and %d", v.name, v.min, v.max)
		}
	}
	if l.MaxDescriptionBytes > l.MaxReviewBytes {
		return fmt.Errorf("max_description_bytes must not exceed max_review_bytes")
	}
	return nil
}

// LimitsFromEnv reads optional settings without consulting process state itself.
func LimitsFromEnv(lookup func(string) (string, bool)) (Limits, error) {
	l := Defaults()
	for _, v := range []struct {
		name   string
		target *int
	}{
		{"ANONCE_MAX_QUESTIONS", &l.MaxQuestions},
		{"ANONCE_MAX_REVIEW_BYTES", &l.MaxReviewBytes},
		{"ANONCE_MAX_DESCRIPTION_BYTES", &l.MaxDescriptionBytes},
		{"ANONCE_MAX_RESPONSE_BYTES", &l.MaxResponseBytes},
	} {
		if raw, ok := lookup(v.name); ok {
			n, err := strconv.Atoi(raw)
			if err != nil {
				return Limits{}, fmt.Errorf("%s must be an integer: %w", v.name, err)
			}
			*v.target = n
		}
	}
	if err := l.Validate(); err != nil {
		return Limits{}, err
	}
	return l, nil
}

// Public includes fixed wire-format bounds alongside effective deployment policy.
func (l Limits) Public() map[string]int {
	l = l.Effective()
	return map[string]int{
		"max_questions": l.MaxQuestions, "max_review_bytes": l.MaxReviewBytes,
		"max_description_bytes": l.MaxDescriptionBytes, "max_response_bytes": l.MaxResponseBytes,
		"max_descriptor_bytes": MaxDescriptorBytes, "pending_padding_bytes": PendingPaddingBytes,
		"anonymous_request_bytes": AnonymousRequestBytes, "max_question_label_bytes": MaxQuestionLabelBytes,
		"max_choices": MaxChoices, "max_choice_label_bytes": MaxChoiceLabelBytes,
	}
}
