package main

import (

	//"github.com/go-echarts/go-echarts/v2/charts"
	//"github.com/go-echarts/go-echarts/v2/opts"

	"image/color"
	"strings"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

//To use this, get with 'go get gonum.org/v1/plot/...'
//go mod init <our_project_name>
//go mod tidy

//https://github.com/gonum/plot/wiki/Example-plots

/*func generateBarItems() []opts.BarData {
	items := make([]opts.BarData, 0)
	for i := 0; i < itemCnt; i++ {
		items = append(items, opts.BarData{Value: rand.Intn(300)})
	}
	return items
}*/

const (
	metricCompletionTime = "Avg Completion Time - Client (ms)"
	metricCHTime         = "Avg Write Client Hello Time (ms)"
	metricPSHTime        = "Avg Process Server Hello - Client (ms)"
	metricWKEMCtTime     = "Avg Write KEM Ciphertext - Client (ms)"
)

//Dimgray
var barsGraphColor = color.RGBA{R: 105, G: 105, B: 105, A: 255}

func resultsToArray(results []ClientResultsInfo) (rArrayNames []string, rArrayTotalTime plotter.Values,
	rArrayCHello plotter.Values, rArrayPSHello plotter.Values, rArrayWKEMCt plotter.Values) {

	for _, r := range results {
		rArrayNames = append(rArrayNames, r.kexName)
		rArrayTotalTime = append(rArrayTotalTime, r.avgTotalTime)
		rArrayCHello = append(rArrayCHello, r.avgWriteClientHello)
		rArrayPSHello = append(rArrayPSHello, r.avgProcessServerHello)
		rArrayWKEMCt = append(rArrayWKEMCt, r.avgWriteKEMCiphertext)
	}
	return rArrayNames, rArrayTotalTime, rArrayCHello, rArrayPSHello, rArrayWKEMCt
}

/*
 * Bar chart from gonum/plot
 */
func genbar(results []ClientResultsInfo, metric string) {

	names, resultsTotalTime, resultsCH, resultsPSH, resultsWKEMCt := resultsToArray(results)

	var groupBar plotter.Values
	switch metric {
	default:
		groupBar = resultsTotalTime
	case metricCHTime:
		groupBar = resultsCH
	case metricPSHTime:
		groupBar = resultsPSH
	case metricWKEMCtTime:
		groupBar = resultsWKEMCt
	}

	p := plot.New()
	p.Y.Label.Text = metric
	p.Title.Text = "Bar"
	w := vg.Points(20)

	barsA, err := plotter.NewBarChart(groupBar, w)
	if err != nil {
		panic(err)
	}
	barsA.LineStyle.Width = vg.Length(0)
	barsA.Color = barsGraphColor //plotutil.Color(0)

	p.Add(barsA)
	//p.Legend.Add("Client Total Time", barsA)
	p.Legend.Top = true
	p.NominalX(names...)

	if err := p.Save(9*vg.Inch, 4*vg.Inch, "barchart"+strings.TrimSpace(metric)+".pdf"); err != nil {
		panic(err)
	}
}

/*
 * Boxplot chart from gonum/plot
 */
func boxplot(names []string, vals []plotter.Values, hs int) {

	// Create the plot and set its title and axis label.
	p := plot.New()

	p.Title.Text = "Box plots"
	p.Y.Label.Text = "Handshake completion times (ms)"

	//values
	count := 0.0
	for _, v := range vals {
		// Make boxes for our data and add them to the plot.
		w := vg.Points(40)

		//add a box
		box, err := plotter.NewBoxPlot(w, count, v)
		box.FillColor = barsGraphColor
		if err != nil {
			panic(err)
		}
		count++
		p.Add(box)
	}

	// Set the X axis of the plot to nominal with
	// the given names for x=0, x=1 and x=2.
	p.NominalX(names...)

	if err := p.Save(9*vg.Inch, 4*vg.Inch, "boxplot.pdf"); err != nil {
		panic(err)
	}
}
