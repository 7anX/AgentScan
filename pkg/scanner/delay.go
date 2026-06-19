package scanner

import (
	"math/rand"
	"time"
)

// scanDelay sleeps for delayMs ± 30% random jitter.
// When delayMs <= 0 this is a no-op.
func scanDelay(delayMs int) {
	if delayMs <= 0 {
		return
	}
	jitter := delayMs * 30 / 100 // ±30%
	actual := delayMs
	if jitter > 0 {
		actual = delayMs - jitter + rand.Intn(jitter*2+1)
	}
	time.Sleep(time.Duration(actual) * time.Millisecond)
}
