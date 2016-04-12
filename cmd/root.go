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
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "nessusControl",
	Short: "Nessus Control is used to control a Nessus infrastructure from your command line",
	Long: `Nessus Control is a CLI tool designed to control a Nessus infrastructure.

This includes automatically creating scans, exporting results, processing the
results, and storing the processed results in a MySQL database. During
processing, tasks such as rewriting severity of a plugin may occur`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags, which, if defined here,
	// will be global for your application.

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.nessusControl.yaml)")
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	RootCmd.PersistentFlags().StringP("username", "u", "admin", "The username to log into Nessus.")
	RootCmd.PersistentFlags().StringP("password", "a", "Th1sSh0u1dB3AStr0ngP422w0rd", "The password to use to log into Nessus.")
	RootCmd.PersistentFlags().StringP("hostname", "o", "127.0.0.1", "The host where Nessus is located.")
	RootCmd.PersistentFlags().StringP("port", "p", "8834", "The port number used to connect to Nessus.")
	RootCmd.PersistentFlags().BoolP("debug", "d", false, "Use this flag to enable debug mode")

	viper.BindPFlag("auth.username", RootCmd.PersistentFlags().Lookup("username"))
	viper.SetDefault("auth.username", "admin")
	viper.BindPFlag("auth.password", RootCmd.PersistentFlags().Lookup("password"))
	viper.SetDefault("auth.password", "Th1sSh0u1dB3AStr0ngP422w0rd")
	viper.BindPFlag("nessusLocation.hostname", RootCmd.PersistentFlags().Lookup("hostname"))
	viper.SetDefault("nessusLocation.hostname", "127.0.0.1")
	viper.BindPFlag("nessusLocation.port", RootCmd.PersistentFlags().Lookup("port"))
	viper.SetDefault("nessusLocation.port", "8834")
	viper.BindPFlag("debug", RootCmd.PersistentFlags().Lookup("debug"))
	viper.SetDefault("debug", "8834")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetConfigName(".nessusControl") // name of config file (without extension)
	viper.AddConfigPath("$HOME")          // adding home directory as first search path
	viper.AutomaticEnv()                  // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		viper.WatchConfig()
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
