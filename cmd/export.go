// Copyright © 2016 Kevin Kirsche <kev.kirsche@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"crypto/tls"
	"log"
	"net/http"
	"os/user"

	"github.com/kkirsche/nessusControl/api"
	"github.com/kkirsche/nessusControl/database"
	"github.com/kkirsche/nessusControl/exporter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// exportCmd represents the export command
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Begin the export results pipeline for Nessus",
	Long: `Begins running the export results pipeline to retrieve scan results
from Nessus scans. The export pipeline consists of the following actions:

* Retrieve active scans from SQLite3 database
* Confirm with Nessus that the scan is not running anymore
* Export the scan results as a CSV
* Confirm with Nessus that the scan results export process is complete
* Download the scan to the specified results directory
* Delete the active scan entry in the SQLite3 database

This is done concurrently and will continue to run until all rows are processed.`,
	Run: func(cmd *cobra.Command, args []string) {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient := &http.Client{Transport: transport}
		debugEnabled := false
		apiClient := nessusAPI.NewUsernameClient(viper.GetString("nessusLocation.hostname"),
			viper.GetString("nessusLocation.port"), viper.GetString("auth.username"),
			viper.GetString("auth.password"), viper.GetBool("debug"))

		apiClient, err := apiClient.CreateSession(httpClient)
		if err != nil {
			log.Panicln(err)
		}

		nessusDB, err := nessusDatabase.ConnectToSQLite(viper.GetString("sqlitePath"))
		if err != nil {
			log.Panicln(err)
		}

		fileLocations := nessusExporter.NewFileLocations(viper.GetString("directories.base"),
			viper.GetString("directories.results"))

		exporter := nessusExporter.NewExporter(apiClient, httpClient, nessusDB, fileLocations, debugEnabled)
		err = exporter.ExportResultPipeline()
		if err != nil {
			log.Panicln(err)
		}
	},
}

func init() {
	RootCmd.AddCommand(exportCmd)
	usr, _ := user.Current()

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	exportCmd.PersistentFlags().StringP("basepath", "b", usr.HomeDir, "The base path to the results directory")
	exportCmd.PersistentFlags().StringP("resultspath", "r", "/nessusResults", "The relative path to the results directory from the base directory")

	viper.BindPFlag("directories.base", exportCmd.PersistentFlags().Lookup("basepath"))
	viper.BindPFlag("directories.results", exportCmd.PersistentFlags().Lookup("resultspath"))

	viper.SetDefault("directories.base", usr.HomeDir)
	viper.SetDefault("directories.results", "/nessusResults")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// exportCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
