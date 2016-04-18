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
	"fmt"
	"log"
	"net/http"

	"github.com/kkirsche/nessusControl/api"
	"github.com/kkirsche/nessusControl/creator"
	"github.com/kkirsche/nessusControl/database"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ingestCmd represents the ingest command
var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Begin the ingest pipeline for Nessus",
	Long: `Begins running the ingest requested scan pipeline to start Nessus
scans. The ingest pipeline consists of the following actions:

* Create required directories which don't exist
* Concurrently process the requested scan file directory.
* For each requested scan file, create a new scan
* Launch the created scan
* Create the SQLite3 database table if it does not exist
* Save the launched scan's information to the SQLite3 database

This is done concurrently and will continue to run until all requested scan
files are processed.`,
	Run: func(cmd *cobra.Command, args []string) {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient := &http.Client{Transport: transport}
		debugEnabled := viper.GetBool("debug")
		moveFilesDuringPipeline := false
		apiClient := nessusAPI.NewUsernameClient(viper.GetString("nessusLocation.hostname"),
			viper.GetString("nessusLocation.port"), viper.GetString("auth.username"),
			viper.GetString("auth.password"), debugEnabled)

		apiClient, err := apiClient.CreateSession(httpClient)
		if err != nil {
			log.Panicln(err)
		}

		sqlitePath := viper.GetString("sqlitePath")
		if debugEnabled {
			fmt.Printf("Connecting to database: %s\n", sqlitePath)
		}

		nessusDB, err := nessusDatabase.ConnectToSQLite(sqlitePath)
		if err != nil {
			log.Panicln(err)
		}

		if debugEnabled {
			fmt.Printf("Connected to database %s.\n", sqlitePath)
		}

		if apiClient == nil {
			fmt.Println("API Client is nil. Please contact the developer.")
		}

		if httpClient == nil {
			fmt.Println("HTTP Client is nil. Please contact the developer.")
		}

		if nessusDB == nil {
			fmt.Println("Nessus DB is nil. Please contact the developer.")
		}

		ingestBasePath := viper.GetString("directories.ingest_base_path")
		creator := nessusCreator.NewCreator(ingestBasePath, apiClient, httpClient, nessusDB, debugEnabled)

		if debugEnabled {
			fmt.Println("Creator successfully created. Launching the ingest pipeline")
		}

		err = creator.IngestPipeline(moveFilesDuringPipeline)
		if err != nil {
			log.Panicln(err)
		}
	},
}

func init() {
	RootCmd.AddCommand(ingestCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	ingestCmd.PersistentFlags().StringP("sqlitePath", "s", "/opt/scanner/nessusControl.db", "The path to the Nessus SQLite database.")
	viper.BindPFlag("sqlitePath", ingestCmd.PersistentFlags().Lookup("sqlitePath"))

	ingestCmd.PersistentFlags().StringP("ingest-base-path", "i", "/opt/scanner", "The base path to Nessus request scan files. From here, <ingest-base-path>/targets/incoming, <ingest-base-path>/targets/archive, and <ingest-base-path>/targets/temp<pid> will be used.")
	viper.BindPFlag("directories.ingest_base_path", ingestCmd.PersistentFlags().Lookup("ingest-base-path"))
	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// ingestCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
