# Real-time PII Defense (Veena Rajput)

## Files
- `detector_full_veena_rajput.py` — single-file script to detect + redact PII.
- `redacted_output_veena_rajput.csv` — output generated from the dataset.
- `deployment_strategy.md` — proposal for where/how to deploy the solution.

## Run
```bash
python3 detector_full_veena_rajput.py iscp_pii_dataset.csv
```

## Output Format
CSV with columns:
- `record_id`
- `redacted_data_json`
- `is_pii`

Example:
```
1,"{""phone"": ""98XXXXXX10"", ""order_value"": 1299}",True
```
                              
