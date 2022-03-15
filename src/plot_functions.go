package main

import (

	//"github.com/go-echarts/go-echarts/v2/charts"
	//"github.com/go-echarts/go-echarts/v2/opts"

	"image/color"
	"io"
	"os"
	"regexp"
	"strings"
	"fmt"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
	"math"
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
var hybridBarsGraphColor = color.RGBA{R: 0, G: 0, B: 0, A: 255}


//Security levels
var nistLevels = [][]string{
	{"Kyber512", "LightSaber_KEM", "NTRU_HPS_2048_509"},
	{"P256_Kyber512", "P256_LightSaber_KEM", "P256_NTRU_HPS_2048_509"},
	{"Kyber768", "Saber_KEM", "NTRU_HPS_2048_677", "NTRU_HRSS_701"},
	{"P384_Kyber768", "P384_Saber_KEM", "P384_NTRU_HPS_2048_677", "P384_NTRU_HRSS_701"},
	{"Kyber1024", "FireSaber_KEM", "NTRU_HPS_4096_821", "NTRU_HPS_4096_1229","NTRU_HRSS_1373"},
	{"P521_Kyber1024", "P521_FireSaber_KEM", "P521_NTRU_HPS_4096_821", "P521_NTRU_HPS_4096_1229", "P521_NTRU_HRSS_1373"},
}
var nistLevelsTogether = [][]string{
	{"Kyber512", "P256_Kyber512", "LightSaber_KEM", "P256_LightSaber_KEM", "NTRU_HPS_2048_509", "P256_NTRU_HPS_2048_509"},
	{"Kyber768", "P384_Kyber768", "Saber_KEM", "P384_Saber_KEM", "NTRU_HPS_2048_677", "P384_NTRU_HPS_2048_677", "NTRU_HRSS_701", "P384_NTRU_HRSS_701"},
	{"Kyber1024", "P521_Kyber1024", "FireSaber_KEM", "P521_FireSaber_KEM", "NTRU_HPS_4096_821", "P521_NTRU_HPS_4096_821", "NTRU_HPS_4096_1229",  "P521_NTRU_HPS_4096_1229","NTRU_HRSS_1373",   "P521_NTRU_HRSS_1373"},	
}


func resultsToArray(results []KEMTLSClientResultsInfo, row []string) (rArrayNames []string, rArrayTotalTime plotter.Values,
	rArrayCHello plotter.Values, rArrayPSHello plotter.Values, rArrayWKEMCt plotter.Values) {

	for _, algo := range row {		
		for _, r := range results {
			if algo == r.kexName {
				rArrayNames = append(rArrayNames, r.kexName)
				rArrayTotalTime = append(rArrayTotalTime, r.avgTotalTime)
				rArrayCHello = append(rArrayCHello, r.avgWriteClientHello)
				rArrayPSHello = append(rArrayPSHello, r.avgProcessServerHello)
				rArrayWKEMCt = append(rArrayWKEMCt, r.avgWriteKEMCiphertext)
			}
		}
	}
	return rArrayNames, rArrayTotalTime, rArrayCHello, rArrayPSHello, rArrayWKEMCt
}

func switcherType(metric string, rArrayTotalTime plotter.Values, rArrayCHello plotter.Values, rArrayPSHello plotter.Values, rArrayWKEMCt plotter.Values) (groupBar plotter.Values){
	
	switch metric {
	default:
		groupBar = rArrayTotalTime
	case metricCHTime:
		groupBar = rArrayCHello
	case metricPSHTime:
		groupBar = rArrayPSHello
	case metricWKEMCtTime:
		groupBar = rArrayWKEMCt
	}
	return groupBar
}

/*
 * Bar chart from gonum/plot
 */
func genbar(results []KEMTLSClientResultsInfo, metric string) {	
	//for i, row := range nistLevels{
	nistLevel := 1
	for i := 0; i < 6 ; i+=2 {
		
		/*if (i %2 == 0){
			fmt.Println("Saving PQC-only bar graphs:" +  fmt.Sprintf("%d", i+1) + "...")
			rType = "PQC"
		}else{
			fmt.Println("Saving Hybrid bar graphs:" +  fmt.Sprintf("%d", i+1) + "...")
			rType = "Hybrid"
		}*/
		fmt.Println("Saving Bar graphs level:" +  fmt.Sprintf("%d", nistLevel) + "/"+strings.ReplaceAll(metric, " ", "")+"...")		
		names, resultsTotalTime, resultsCH, resultsPSH, resultsWKEMCt := resultsToArray(results,nistLevels[i])
		
		//select desired metric
		groupBar := switcherType(metric, resultsTotalTime, resultsCH, resultsPSH, resultsWKEMCt)

		p := plot.New()
		p.X.Min = 0
		p.Y.Min = 0
		p.Y.Label.Text = metric
		p.Title.Text = "Bar NIST level" + fmt.Sprintf("%d", nistLevel)
		w := vg.Points(10)

		//PQC-only
		barsA, err := plotter.NewBarChart(groupBar, w)
		if err != nil {
			panic(err)
		}
		barsA.LineStyle.Width = vg.Length(0)
		barsA.Color = barsGraphColor //plotutil.Color(0)

		p.Add(barsA)

		//Hybrid
		_, resultsTotalTimeHybrid, resultsCHHybrid, resultsPSHHybrid, resultsWKEMCtHybrid := resultsToArray(results,nistLevels[i+1])
		groupBar = switcherType(metric, resultsTotalTimeHybrid, resultsCHHybrid, resultsPSHHybrid, resultsWKEMCtHybrid)
		barsB, err := plotter.NewBarChart(groupBar, w)
		if err != nil {
			panic(err)
		}
		barsB.LineStyle.Width = vg.Length(0)
		barsB.Color = hybridBarsGraphColor //plotutil.Color(0)
		barsB.Offset = w
		p.Add(barsB)				

		//p.Legend.Add("Client Total Time", barsA)
		p.Legend.Add("PQC", barsA)
		p.Legend.Add("Hybrid", barsB)		
		p.Legend.Top = true
		p.Legend.XOffs = -1
		p.Legend.YOffs = 12
		//p.Legend.ThumbnailWidth = 0.5 * vg.Inch
		p.NominalX(names...)
		p.Add(plotter.NewGrid())

		if err := p.Save(7*vg.Inch, 3*vg.Inch, "graphs/bar-"+fmt.Sprintf("%d", nistLevel)+"-"+strings.ReplaceAll(metric, " ", "")+".pdf"); err != nil {
			panic(err)
		}
		nistLevel += 2
	}

}

/*
 * Boxplot chart from gonum/plot
 */
func boxplot(names []string, vals []plotter.Values, hs int) {

	// Create the plot and set its title and axis label.
	p := plot.New()

	fmt.Println("Saving Boxplot for hybrid KEMTLS...")

	p.Title.Text = "Box plots"
	p.Y.Label.Text = "Handshake completion times (ms)"
	p.X.Min = 0
	p.Y.Min = 0
	//values
	count := 0.0
	for _, v := range vals {
		// Make boxes for our data and add them to the plot.
		w := vg.Points(20)

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
	
	/*p.Legend.Add("Hybrid", barsB)		
	p.Legend.Top = true
	p.Legend.XOffs = -1
	p.Legend.YOffs = 12*/			
	p.Add(plotter.NewGrid())

	if err := p.Save(12*vg.Inch, 4*vg.Inch, "graphs/boxplot-hybrids.pdf"); err != nil {
		panic(err)
	}
}

/*
 * Go-echarts for hybrid penalty computation
 */

//get data for the plot
//datatype is PQC-only or Hybrid
func getBarItems(results []KEMTLSClientResultsInfo, datatype string,selection string) (items []opts.BarData, names []string) {

	items = make([]opts.BarData, 0)

	re := regexp.MustCompile(`P256|P384|P521|x25519|x448`)	
	reReplace := regexp.MustCompile(`P256_|P384_|P521_`)

	for _, r1 := range results {
		if datatype == "PQC-only" {
			if !re.MatchString(r1.kexName) {
				items = append(items, opts.BarData{Name: r1.kexName,
					Value: math.Round(r1.avgTotalTime*100)/100 })
				names = append(names, r1.kexName)
			}
		} else {
			if re.MatchString(r1.kexName) {
				resultStr := reReplace.ReplaceAllString(r1.kexName,"")
				items = append(items, opts.BarData{Name: resultStr,
					Value: math.Round(r1.avgTotalTime*100)/100 })
			}
		}
	}

	return items, names
}
//selection is "All" or "L1"
func barMarkLines(results []KEMTLSClientResultsInfo, selection string) { //*charts.Bar {
	bar := charts.NewBar()

	dataPQC, pqcNames := getBarItems(results, "PQC-only", selection)
	dataHybrid, _ := getBarItems(results, "Hybrid", selection)

	//labels
	bar.SetGlobalOptions(				
		charts.WithTitleOpts(opts.Title{
			Title: "Hybrid and PQC-Only Results",
		}),
		charts.WithToolboxOpts(opts.Toolbox{Show: true}),		
		charts.WithTooltipOpts(opts.Tooltip{Show: true}),		
		charts.WithLegendOpts(opts.Legend{Right: "50%", Orient: "vertical"}),
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
			End:   100,
		}),
		charts.WithInitializationOpts(opts.Initialization{
			Width:  "1600px",
			Height: "650px",
		}),
		charts.WithDataZoomOpts(opts.DataZoom{
			Type:  "inside",
			Start: 10,
			End:   50,
		}),
		charts.WithToolboxOpts(opts.Toolbox{
			Show:  true,
			Right: "5%",
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{
					Show:  true,
					Type:  "png",
					Title: "Download PNG",
				},
				DataView: &opts.ToolBoxFeatureDataView{
					Show:  true,
					Title: "DataView",
					Lang: []string{"data view", "turn off", "refresh"},
				},
			}},
		),
	)
	
	bar.SetXAxis(pqcNames).
	//bar.SetXAxis([]string{"Kyber", "Kyber", "Kyber", "Saber", "Saber","Saber", "NTRU", "NTRU","NTRU","NTRU", "NTRU", "NTRU"}).
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
	f, err := os.Create("graphs/kemtls-pqcAndHybrid.html")
	if err != nil {
		panic(err)
	}
	page.Render(io.MultiWriter(f))
}