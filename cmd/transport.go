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
	"fmt"
	"log"

	"github.com/kkirsche/nessusControl/transporter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// transportCmd represents the transport command
var transportCmd = &cobra.Command{
	Use:   "transport",
	Short: "Transports remote files to the local machine",
	Long: `Transport is used to transport Nessus result files on a scanner to the
local machine, usually for further processing.`,
	Run: func(cmd *cobra.Command, args []string) {
		scanners := viper.GetStringSlice("transport.scanners")
		withDebug := viper.GetBool("debug")
		for _, scanner := range scanners {
			if withDebug {
				fmt.Printf("Transporting files from %s\n", scanner)
			}

			transportBase := "transport." + scanner
			sshKey := nessusTransporter.NewSSHKey(viper.GetString(transportBase+".key.basepath"), viper.GetString(transportBase+".key.filename"))
			sshAuth := nessusTransporter.NewSSHAuth(viper.GetString(transportBase+".auth.username"), viper.GetString(transportBase+".auth.password"))
			targetHost := nessusTransporter.NewTargetHost(viper.GetString(transportBase+".address.host"), viper.GetString(transportBase+".address.port"))
			withSSHAgent := viper.GetBool(transportBase + ".withSSHAgent")

			transporter := nessusTransporter.NewTransporter(sshKey, sshAuth, targetHost, withSSHAgent, withDebug)
			err := transporter.Connect()
			if err != nil {
				log.Panicln(err)
			}

			err = transporter.RetrieveResultFiles(viper.GetString(transportBase+".resultPath"),
				viper.GetString("directories.base")+viper.GetString("directories.results"),
				viper.GetBool(transportBase+"removeResultFiles"))
			if err != nil {
				log.Panicln(err)
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(transportCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// transportCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// transportCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
