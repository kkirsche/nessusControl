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
	"github.com/kkirsche/nessusControl/creator"
	"github.com/kkirsche/nessusControl/database"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ingestCmd represents the ingest command
var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Begin the ingest pipeline for Nessus",
	Long: `Begins running the ingest pipeline to create and launch new Nessus
scans.`,
	Run: func(cmd *cobra.Command, args []string) {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient := &http.Client{Transport: transport}
		debugEnabled := false
		moveFilesDuringPipeline := false
		apiClient := nessusAPI.NewUsernameClient(viper.GetString("nessusLocation.hostname"),
			viper.GetString("nessusLocation.port"), viper.GetString("auth.username"),
			viper.GetString("auth.password"), viper.GetBool("debug"))

		apiClient, err := apiClient.CreateSession(httpClient)
		if err != nil {
			log.Fatal(err.Error())
		}

		nessusDB, err := nessusDatabase.ConnectToSQLite(viper.GetString("sqlitePath"))
		if err != nil {
			log.Fatal(err.Error())
		}

		creator := nessusCreator.NewCreator(viper.GetString("directories.base")+
			viper.GetString("directories.incoming"), apiClient, httpClient, nessusDB,
			debugEnabled)
		err = creator.IngestPipeline(moveFilesDuringPipeline)
		if err != nil {
			log.Fatal(err.Error())
		}
	},
}

func init() {
	RootCmd.AddCommand(ingestCmd)
	usr, _ := user.Current()

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	ingestCmd.PersistentFlags().StringP("sqlitePath", "s", usr.HomeDir+"/nessusIncoming", "The path to the Nessus SQLite database.")
	viper.BindPFlag("sqlitePath", ingestCmd.PersistentFlags().Lookup("sqlitePath"))
	viper.SetDefault("sqlitePath", usr.HomeDir+"/nessusControl.db")

	ingestCmd.PersistentFlags().StringP("basepath", "b", usr.HomeDir, "The path to the Nessus request scan files.")
	viper.BindPFlag("directories.base", ingestCmd.PersistentFlags().Lookup("basepath"))
	viper.SetDefault("directories.base", usr.HomeDir)

	ingestCmd.PersistentFlags().StringP("requestedPath", "r", "/nessusRequestedScans", "The relative path to the Nessus request scan files from the base directory.")
	viper.BindPFlag("directories.incoming", ingestCmd.PersistentFlags().Lookup("requestedPath"))
	viper.SetDefault("directories.incoming", "/nessusRequestedScans")
	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// ingestCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
