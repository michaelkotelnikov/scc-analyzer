package main

import (
	"flag"
	"fmt"
	"os"
	"scc-analyzer/pkg/analyzer"
	"scc-analyzer/pkg/kube"

	"github.com/olekukonko/tablewriter"
)

func cmdUsage() {
	fmt.Printf("Usage: %s [OPTIONS] argument ...\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	flag.Usage = cmdUsage
	var namespace = flag.String("namespace", "default", "Specify the Namespace to run the analyzer on.")
	flag.Parse()

	context := ""

	client, err := kube.NewClient(context)
	if err != nil {
		fmt.Println(err)
	}

	perms, err := analyzer.BuildPermissions(client, *namespace)
	if err != nil {
		fmt.Println(err)
	}

	rules := analyzer.BuildRules()

	rows := [][]string{}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Namespace", "Service Account", "Rule Description", "SCC"})
	table.SetAutoMergeCellsByColumnIndex([]int{0, 1})
	table.SetAutoMergeCells(true)
	table.SetRowLine(true)

	for _, sa := range perms.ServiceAccounts {
		saSCC := analyzer.CreateServiceAccountMap(perms, sa)
		for _, scc := range saSCC.SecurityContextConstraints {
			evaluations := rules.EvaluateSCC(&scc)
			for _, evaluation := range evaluations {
				row := []string{*namespace, sa.Name, evaluation, scc.Name}
				rows = append(rows, row)
			}
		}
	}

	table.AppendBulk(rows)
	table.Render()
}
