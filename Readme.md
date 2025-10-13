## CISA Data

This pipeline automates the process of reading data from a JSON API endpoint, validating record counts, transforming the data, and updating an existing DynamoDB table.
It ensures that any new or updated records are appended with the latest update timestamp.

⚙️ Workflow Steps  
1️⃣ Read JSON from Endpoint

Fetch JSON data from the CISA API endpoint.

Parse the response and load it into memory for processing.

2️⃣ Validate Record Count

Count the number of records in the fetched JSON.

Retrieve the current record count from DynamoDB.

Compare both counts to detect new or missing records.

3️⃣ Transform Data

If there’s a change in record count:

Add a new column named updated_date to each record.

The value should be the current UTC timestamp.

4️⃣ Update DynamoDB

Identify new records using the unique cve_id key.

Append only the new or changed records to the DynamoDB table.

Ensure idempotent writes (avoid duplicate entries).


## Exploit


## EPSS
1. Downlaod json. manually add the updated_date through excel. upload to s3 and upload to dynamodb.
2. read the date column from dyanmodb and get the maximum date. Ex(24/09/2025) 
3. extracting the data after the maximun date and update the records in dynamodb.


