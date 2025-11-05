#!/usr/bin/env python3

import os
import json
from pathlib import Path
def analyze_sarif_files_in_folder(folder_path: Path):
    """
    Analyze all SARIF files in a specified single folder and independently count for each file:
    1. Total number of results (Total Results)
    2. Number of unique file paths (Unique File Paths)
    """
    if not folder_path.is_dir():
        print(f"Error: Directory '{folder_path}' does not exist.")
        return

    print(f"Starting analysis of SARIF files in directory '{folder_path}'...")
    print("-----------------------------------------------------")

    # Find and traverse all .sarif files in the current directory
    sarif_files = sorted(list(folder_path.glob('*.sarif')))
    
    if not sarif_files:
        print("No .sarif files found in this directory.")
        return

    for sarif_file in sarif_files:
        # Use filename (without extension) as project identifier
        project_name = sarif_file.stem
        
        unique_paths = set()
        total_results_count = 0

        try:
            with open(sarif_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for run in data.get('runs', []):
                results_in_run = run.get('results', [])
                total_results_count += len(results_in_run)

                for result in results_in_run:
                    for location in result.get('locations', []):
                        physical_location = location.get('physicalLocation')
                        if physical_location:
                            artifact_location = physical_location.get('artifactLocation')
                            if artifact_location:
                                uri = artifact_location.get('uri')
                                if uri:
                                    unique_paths.add(uri)
                                    
            # Print statistics for each file
            print(f"{project_name}: Total results = {total_results_count}, Unique paths = {len(unique_paths)}")

        except json.JSONDecodeError:
            print(f"Warning: File '{sarif_file.name}' is not valid JSON format, skipped.")
        except Exception as e:
            print(f"Error processing file '{sarif_file.name}': {e}")

    print("-----------------------------------------------------")
    print("Analysis completed.")

def analyze_sarif_files(base_dir: Path):
    """
    Traverse all project folders in the specified directory and count for each project:
    1. Total number of results (Total Results)
    2. Number of unique file paths (Unique File Paths)
    """
    if not base_dir.is_dir():
        print(f"Error: Directory '{base_dir}' does not exist.")
        return

    print(f"Starting analysis of projects in directory '{base_dir}'...")
    print("-----------------------------------------")

    # Traverse each project folder in the root directory
    for project_path in sorted(base_dir.iterdir()):
        if not project_path.is_dir():
            continue

        project_name = project_path.name
        unique_paths = set()
        total_results_count = 0  # New: Counter for total results

        sarif_files = list(project_path.rglob('C*.sarif'))

        if not sarif_files:
            print(f"{project_name}: Total results = 0, Unique paths = 0")
            continue

        for sarif_file in sarif_files:
            try:
                with open(sarif_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                for run in data.get('runs', []):
                    # Directly accumulate the length of 'results' list to get total results
                    results_in_run = run.get('results', [])
                    total_results_count += len(results_in_run)

                    # --- This logic remains unchanged for counting unique paths ---
                    for result in results_in_run:
                        for location in result.get('locations', []):
                            physical_location = location.get('physicalLocation')
                            if physical_location:
                                artifact_location = physical_location.get('artifactLocation')
                                if artifact_location:
                                    uri = artifact_location.get('uri')
                                    if uri:
                                        unique_paths.add(uri)
            except Exception as e:
                print(f"Error processing file '{sarif_file}': {e}")

        # Print both statistical results
        print(f"{project_name}: Total results = {total_results_count}, Unique paths = {len(unique_paths)}")

    print("-----------------------------------------")
    print("Analysis completed.")

if __name__ == "__main__":
    SARIF_BASE_DIRECTORY = Path("")
    newPath = Path("")
    Internal_Path = Path("")
    sec_code = Path("")
    analyze_sarif_files(SARIF_BASE_DIRECTORY)
    analyze_sarif_files_in_folder(newPath)
    analyze_sarif_files_in_folder(Internal_Path)
    analyze_sarif_files_in_folder(sec_code)
