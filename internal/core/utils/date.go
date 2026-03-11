package utils

import (
	"fmt"
	"time"
)

func FormatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60

	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%d hours %d minutes", h, m)
	case h > 0:
		return fmt.Sprintf("%d hours", h)
	default:
		return fmt.Sprintf("%d minutes", m)
	}
}
