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
	errCh := make(chan error)

	var requestIDs []int
	for rows.Next() {
		wg.Add(1)
		var launchedScanRow launchedScanDBRow
		rows.Scan(&launchedScanRow.requestID, &launchedScanRow.method, &launchedScanRow.scanUUID, &launchedScanRow.scanID, &launchedScanRow.scanStartTime)
		go func(wg *sync.WaitGroup, e *Exporter, launchedScanRow launchedScanDBRow, requestIDs []int) {
			details, forLoopErr := e.apiClient.ScanDetails(e.httpClient, launchedScanRow.scanID)
			if forLoopErr != nil {
				errCh <- forLoopErr
				wg.Done()
				return
			}

			for details.Info.Status == "running" {
				time.Sleep(10000)
				details, forLoopErr = e.apiClient.ScanDetails(e.httpClient, launchedScanRow.scanID)
				if forLoopErr != nil {
					errCh <- forLoopErr
					wg.Done()
					return
				}
			}

			exportedFileResponse, forLoopErr := e.apiClient.ExportScan(e.httpClient, launchedScanRow.scanID, `{"format":"csv"}`)
			if forLoopErr != nil {
				errCh <- forLoopErr
				wg.Done()
				return
			}

			readyToExport := false
			for readyToExport {
				status, forErr := e.apiClient.ScanExportStatus(e.httpClient, launchedScanRow.scanID, exportedFileResponse.File)
				if forErr != nil {
					errCh <- forErr
					wg.Done()
					return
				}

				if status.Status == "ready" {
					readyToExport = true
					continue
				}

				time.Sleep(10000)
			}

			scanResults, forLoopErr := e.apiClient.DownloadScan(e.httpClient, launchedScanRow.scanID, exportedFileResponse.File)
			if forLoopErr != nil {
				errCh <- forLoopErr
				wg.Done()
				return
			}
			filename := fmt.Sprintf("Scanner_%s-RequestID_%d-Method_%s-ScanId_%d-Time_%s.csv", getLocalIPAddress(), launchedScanRow.requestID, launchedScanRow.method, launchedScanRow.scanID, launchedScanRow.scanStartTime)
			filepath := fmt.Sprintf("%s/%s", e.fileLocations.resultsDirectory, filename)
			forLoopErr = ioutil.WriteFile(filepath, []byte(scanResults), 0644)
			if forLoopErr != nil {
				errCh <- forLoopErr
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

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}

	for _, requestID := range requestIDs {
		_, err = e.sqliteDB.Exec("DELETE FROM active_scans WHERE scan_id = $a;", requestID)
		if err != nil {
			return err
		}
	}

	return nil
}
