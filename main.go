package main

import (
	"flag"
	"io"
	"log"
	"os"

	"github.com/michaelkotelnikov/scc-analyzer/pkg/analyzer"
	"github.com/michaelkotelnikov/scc-analyzer/pkg/kube"

	"github.com/olekukonko/tablewriter"
)

func cmdUsage() {
	message := "Usage: " + os.Args[0] + " [OPTIONS] argument ...\n"

	_, err := io.WriteString(os.Stdout, message)
	if err != nil {
		log.Fatalf("Error: %v", err)

		return
	}

	flag.PrintDefaults()
}

func main() {
	flag.Usage = cmdUsage

	namespace := flag.String(
		"namespace",
		"default",
		"Specify the Namespace to run the analyzer on.",
	)

	expand := flag.Bool(
		"expand",
		false,
		"Use flag to visualize SCC rule description",
	)

	flag.Parse()

	context := ""

	client, err := kube.NewClient(context)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	perms, err := analyzer.BuildPermissions(client, *namespace)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	var rules *analyzer.Rules
	if *expand {
		rules = analyzer.BuildRules()
	}

	rows := generateRows(perms, rules, *namespace, *expand)

	printTable(rows, *expand)
}

func generateRows(perms *analyzer.Permissions, rules *analyzer.Rules, namespace string, expand bool) [][]string {
	var rows [][]string

	for _, serviceAccount := range perms.ServiceAccounts {
		saSCC := analyzer.CreateServiceAccountMap(perms, serviceAccount)
		for _, scc := range saSCC.SecurityContextConstraints {
			if expand {
				evaluations := rules.EvaluateSCC(scc)
				for _, evaluation := range evaluations {
					row := []string{namespace, serviceAccount.Name, evaluation, scc.Name}
					rows = append(rows, row)
				}
			} else {
				row := []string{namespace, serviceAccount.Name, scc.Name}
				rows = append(rows, row)
			}
		}
	}

	return rows
}

func printTable(rows [][]string, expand bool) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0, 1})

	if expand {
		table.SetHeader([]string{
			"Namespace",
			"Service Account",
			"Rule Description",
			"SCC",
		})
	} else {
		table.SetHeader([]string{
			"Namespace",
			"Service Account",
			"SCC",
		})
	}

	table.AppendBulk(rows)
	table.Render()
}
