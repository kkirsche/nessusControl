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
	"log"

	"github.com/kkirsche/nessusControl/transporter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// transportCmd represents the transport command
var transportCmd = &cobra.Command{
	Use:   "transport",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		scanners := viper.GetStringSlice("transport.scanners")

		for _, scanner := range scanners {
			transporter := nessusTransporter.NewTransporter(
				nessusTransporter.NewSSHKey(viper.GetString("transport.key.basepath"), viper.GetString("transport.key.filename."+scanner)),
				nessusTransporter.NewSSHAuth(viper.GetString("transport.auth."+scanner+".username"), viper.GetString("transport.auth."+scanner+".password")),
				nessusTransporter.NewTargetHost(viper.GetString("transport.connectionInfo."+scanner+".host"), viper.GetString("transport.connectionInfo."+scanner+".port")),
				viper.GetBool("transport.auth."+scanner+".withSSHAgent"))

			err := transporter.Connect()
			if err != nil {
				log.Fatal(err)
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