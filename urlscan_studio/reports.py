import csv
import io


def csv_report(job):
    output=io.StringIO(newline="")
    writer=csv.writer(output)
    writer.writerow(["url","state","verdict","score","http_status","country","source","cached","error"])
    for item in job["items"]:
        result=item["result"] or {}
        values=[item["url"],item["status"],result.get("verdict","unknown"),result.get("score"),result.get("http_status"),result.get("country"),result.get("source",job["provider"]),item["cached"],item["error"]]
        writer.writerow(["'"+value if isinstance(value,str) and value.lstrip().startswith(("=","+","-","@")) else value for value in values])
    return output.getvalue()
