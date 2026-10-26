package slide

import (
	"math"

	"github.com/sparklyi/bouncer"
)

// trustedTrajectory applies two bands of rules.
//
// Hard failures are physically impossible or trivially synthetic traces (too
// few points, non-monotone time, impossible distance). Scoring failures are
// statistical: three or more implausible shape features reject the trace.
//
// The rules are published on purpose. A secret heuristic would create a false
// sense of security; per-deployment jitter of the thresholds is the actual
// mitigation against targeted bypass.
func trustedTrajectory(events []bouncer.PointerEvent, width, height, piece, tol int) bool {
	if len(events) < 5 || len(events) > 512 {
		return false
	}
	first, last := events[0], events[len(events)-1]
	duration := float64(last.T - first.T)
	if duration <= 0 || duration > 20_000 {
		return false
	}
	dx := abs(last.X - first.X)
	if abs(last.X) > 3*width || abs(first.X) > 3*width {
		return false
	}
	if dx > 2*width {
		return false
	}
	if dx > 100 && len(events) < 8 {
		return false
	}

	var velocities []float64
	nonPositive := 0
	reversals := 0
	prevDir := 0
	for i := 1; i < len(events); i++ {
		dt := float64(events[i].T - events[i-1].T)
		step := events[i].X - events[i-1].X
		if dt <= 0 {
			nonPositive++
			continue
		}
		velocities = append(velocities, math.Abs(float64(step))/dt)
		if step > 1 {
			if prevDir < 0 {
				reversals++
			}
			prevDir = 1
		} else if step < -1 {
			if prevDir > 0 {
				reversals++
			}
			prevDir = -1
		}
	}
	if nonPositive > len(events)/3 || len(velocities) < 4 {
		return false
	}

	var sum, maxV float64
	for _, v := range velocities {
		sum += v
		if v > maxV {
			maxV = v
		}
	}
	meanV := sum / float64(len(velocities))
	if meanV <= 0 {
		return false
	}
	lastV := velocities[len(velocities)-1]
	ratio := maxV / meanV

	// Coefficient of variation of the sampling interval.
	var dtSum, dtSq float64
	for i := 1; i < len(events); i++ {
		dt := float64(events[i].T - events[i-1].T)
		if dt <= 0 {
			continue
		}
		dtSum += dt
		dtSq += dt * dt
	}
	dtMean := dtSum / float64(len(velocities))
	dtVar := dtSq/float64(len(velocities)) - dtMean*dtMean
	if dtVar < 0 {
		dtVar = 0
	}
	cv := math.Sqrt(dtVar) / dtMean

	violations := 0
	if ratio < 1.12 || ratio > 10 {
		violations++
	}
	if lastV > 0.55*meanV {
		violations++
	}
	if reversals > 6 {
		violations++
	}
	if cv < 0.05 || cv > 2.5 {
		violations++
	}
	if dx > 100 && duration < 120 {
		violations++
	}
	return violations < 3
}
