package main

import (

	//"github.com/go-echarts/go-echarts/v2/charts"
	//"github.com/go-echarts/go-echarts/v2/opts"

	"image/color"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
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

/*
 * Go-echarts for hybrid penalty computation
 */

//get data for the plot
//datatype is PQC-only or Hybrid
func getBarItems(results []ClientResultsInfo, datatype string) (items []opts.BarData, names []string) {

	/*	var desiredAlgos []string
		if datatype == "PQC-only" {
			desiredAlgos = []string{"P256_Kyber512", "P384_Kyber768", "P521_Kyber1024", "P256_NTRU_HPS_2048_509",
				"P384_NTRU_HPS_2048_677", "P521_NTRU_HPS_4096_821", "P521_NTRU_HPS_4096_1229", "P384_NTRU_HRSS_701",
				"P521_NTRU_HRSS_1373", "P256_LightSaber_KEM", "P384_Saber_KEM", "P521_FireSaber_KEM"}
		} else {
			//desiredAlgosCIRCL = []string{"Kyber1024X448", "Kyber512X25519", "Kyber768X448", "SIKEp434X25519", "SIKEp503X448", "SIKEp751X448"}
			desiredAlgos = []string{"Kyber512", "Kyber768", "Kyber1024", "NTRU-HPS-2048-509",
				"NTRU-HPS-2048-677", "NTRU-HPS-4096-821", "NTRU-HPS-4096-1229", "NTRU-HRSS-701",
				"NTRU-HRSS-1373", "LightSaber-KEM", "Saber-KEM", "FireSaber-KEM"}
		}*/

	items = make([]opts.BarData, 0)
	/*for _, r := range results {
		for _, a := range desiredAlgos {
			if r.kexName == a {
				items = append(items, opts.BarData{Name: r.kexName,
					Value: r.avgTotalTime})
				names = append(names, r.kexName)
				break
			}
		}

	}*/
	re := regexp.MustCompile(`P256|P384|P521|x25519|x448`)

	for _, r1 := range results {
		if datatype == "PQC-only" {
			if !re.MatchString(r1.kexName) {
				items = append(items, opts.BarData{Name: r1.kexName,
					Value: r1.avgTotalTime})
				names = append(names, r1.kexName)
			}
		} else {
			if re.MatchString(r1.kexName) {
				items = append(items, opts.BarData{Name: r1.kexName,
					Value: r1.avgTotalTime})
				names = append(names, r1.kexName)
			}
		}
	}

	/*fmt.Println("\nType:" + datatype + "---")
	for _, n := range items {
		fmt.Print(" " + n.Name)
	}*/

	return items, names
}

func barMarkLines(results []ClientResultsInfo) { //*charts.Bar {
	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{
			Title: "Hybrid and PQC-Only Results",
		}),
	)

	dataPQC, pqcNames := getBarItems(results, "PQC-only")
	dataHybrid, _ := getBarItems(results, "Hybrid")

	//labels
	bar.SetGlobalOptions(
		//charts.WithTitleOpts(opts.Title{Title: "label options"}),
		charts.WithYAxisOpts(opts.YAxis{
			AxisLabel: &opts.AxisLabel{Show: true, Formatter: "{value} ms"},
		}),
		charts.WithColorsOpts(opts.Colors{"dimgray", "black"}),
		charts.WithXAxisOpts(opts.XAxis{
			//Name: "XAxisName",
			SplitLine: &opts.SplitLine{
				Show: true,
			},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name: "Avg Client Time (ms)",
			SplitLine: &opts.SplitLine{
				Show: true,
			},
		}),
		charts.WithDataZoomOpts(opts.DataZoom{
			Type:  "slider",
			Start: 10,
			End:   50,
		}),
	)

	bar.SetXAxis(pqcNames).
		AddSeries("PQC-Only", dataPQC).
		AddSeries("Hybrid", dataHybrid).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:     true,
				Position: "top",
			}),
		)
		//SetSeriesOptions(charts.WithMarkLineNameTypeItemOpts(
		//	opts.MarkLineNameTypeItem{Name: "Maximum", Type: "max"},
		//	opts.MarkLineNameTypeItem{Name: "Minimum", Type: "min"},
		//))
	//save data
	page := components.NewPage()
	page.AddCharts(bar)
	f, err := os.Create("kemtls-pqcAndHybrid.html")
	if err != nil {
		panic(err)
	}
	page.Render(io.MultiWriter(f))
}
