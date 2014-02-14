qualysguard_was_export_csv
==========================

Generate CSV from webapps that were recently scanned by QualysGuard WAS.

Usage
=====

    usage: qualysguard_was_export_csv.py [-h] [-a OVERRIDE_ALL_APPS]
                                         [-D OVERRIDE_DATE] [-d DAYS]
                                         [-o OUTPUT_FILENAME] [-r RESUME] [-t TAG]
                                         [-v] [--config CONFIG]
    
    Generate CSV from webapps that were recently scanned by QualysGuard WAS.
    
    optional arguments:
      -h, --help            show this help message and exit
      -a OVERRIDE_ALL_APPS, --override_all_apps OVERRIDE_ALL_APPS
                            Generate report for all webapps. Automatically
                            selected for first run.
      -D OVERRIDE_DATE, --override_date OVERRIDE_DATE
                            Search scans from DATE_OVERRIDE date (YYYY-MM-DD).
      -d DAYS, --days DAYS  Search scans back DAYS day(s) from today midnight.
      -o OUTPUT_FILENAME, --output_filename OUTPUT_FILENAME
                            Filename of outputted CSV. (Default =
                            qualysguard_was.csv)
      -r RESUME, --resume RESUME
                            Search scans ahead RESUME days from last previous
                            successfully imported date. (Default = 1)
      -t TAG, --tag TAG     Scope import to webapps with TAG tag. Overrides
                            OVERRIDE_ALL_APPS.
      -v, --verbose         Outputs additional information to log.
      --config CONFIG       Configuration for Qualys connector.
