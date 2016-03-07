// Package nessusExporter is used to export results from Nessus when they are
// ready.
package nessusExporter

import (
	"fmt"
	"io/ioutil"
	"sync"
	"time"
)

// ExportResultPipeline is used to check the SQLite database for running scans,
// and begin querying Nessus to find out if a scan is ready to be downloaded to
// the local machine for processing.
func (e *Exporter) ExportResultPipeline() error {
	rows, err := e.sqliteDB.Query("SELECT * FROM active_scans ORDER BY request_id DESC;")
	if err != nil {
		return err
	}
	defer rows.Close()

	wg := new(sync.WaitGroup)

	var requestIDs []int
	for rows.Next() {
		wg.Add(1)
		var launchedScanRow launchedScanDBRow
		rows.Scan(&launchedScanRow.requestID, &launchedScanRow.method, &launchedScanRow.scanUUID, &launchedScanRow.scanID, &launchedScanRow.scanStartTime)
		go func(wg *sync.WaitGroup, e *Exporter, launchedScanRow launchedScanDBRow, requestIDs []int) {
			details, err := e.apiClient.ScanDetails(e.httpClient, launchedScanRow.scanID)
			if err != nil {
				wg.Done()
				return
			}

			for details.Info.Status == "running" {
				time.Sleep(10000)
				details, err = e.apiClient.ScanDetails(e.httpClient, launchedScanRow.scanID)
				if err != nil {
					wg.Done()
					return
				}
			}

			exportedFileResponse, err := e.apiClient.ExportScan(e.httpClient, launchedScanRow.scanID, `{"format":"csv"}`)
			if err != nil {
				wg.Done()
				return
			}

			readyToExport := false
			for readyToExport {
				status, err := e.apiClient.ScanExportStatus(e.httpClient, launchedScanRow.scanID, exportedFileResponse.File)
				if err != nil {
					wg.Done()
					return
				}

				if status.Status == "ready" {
					readyToExport = true
					continue
				}

				time.Sleep(10000)
			}

			scanResults, err := e.apiClient.DownloadScan(e.httpClient, launchedScanRow.scanID, exportedFileResponse.File)
			if err != nil {
				return
			}
			filename := fmt.Sprintf("Scanner_%s-RequestID_%d-Method_%s-ScanId_%d-Time_%s.csv", getLocalIPAddress(), launchedScanRow.requestID, launchedScanRow.method, launchedScanRow.scanID, launchedScanRow.scanStartTime)
			filepath := fmt.Sprintf("%s/%s", e.fileLocations.resultsDirectory, filename)
			err = ioutil.WriteFile(filepath, []byte(scanResults), 0644)
			if err != nil {
				wg.Done()
				return
			}
			requestIDs = append(requestIDs, launchedScanRow.scanID)
			wg.Done()
		}(wg, e, launchedScanRow, requestIDs)
	}

	if err := rows.Err(); err != nil {
		return err
	}

	for _, requestID := range requestIDs {
		_, err = e.sqliteDB.Exec("DELETE FROM active_scans WHERE scan_id = $a;", requestID)
		if err != nil {
			fmt.Print("Delete the row")
			return err
		}
	}

	wg.Wait()

	return nil
}
