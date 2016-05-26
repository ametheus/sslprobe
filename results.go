package sslprobe

type Severity int

var (
	Bonus             Severity = -1
	OK                Severity = 0
	Bad               Severity = 1
	BigFuckingProblem Severity = 2
)

type checkResult struct {
	Label    string
	Severity Severity
	Result   string
}

type checker func(p *Probe) checkResult

var allCheckers map[string]checker = map[string]checker{}

func (p *Probe) OtherChecks() {
	if p.Results != nil {
		return
	}
	p.Results = make(map[string]checkResult)
	for k, f := range allCheckers {
		p.Results[k] = f(p)
	}
}
