import datetime
import mysql.connector
import hashlib
from mysql.connector import errorcode

mydb = mysql.connector.connect(
  host="localhost", 
	port="3306",
  user="root",
  password="root",
  database="snort"
)

mycursor = mydb.cursor()

def transform(line_log):
	line_splitted = line_log.split("[**]")
					# 11/04-21:37:31.632076
	timestamp = line_splitted[0].strip().split("-");
	dat2e = datetime.date(2022,int(timestamp[0].split("/")[1]),int(timestamp[0].split("/")[0]))
	str_date = dat2e.isoformat()

	rule_details = line_splitted[1].strip().split(']')
	rule_id = rule_details[0].replace("[", "").split(":")[1]
	rule_msg = rule_details[1].strip()

	protocol_details = line_splitted[2].split(" ")
	priotity = protocol_details[2].replace("]","")
	service = protocol_details[3].replace("{","").replace("}","")

	source_ip = protocol_details[4].split(":")[0]
	source_port = protocol_details[4].split(":")[1]

	target_ip = protocol_details[6].split(":")[0]
	target_port = protocol_details[6].split(":")[1].replace("\n","")

	hash_diff = hashlib.sha256(line_log.encode('utf-8')).hexdigest()
	val = (str_date, line_splitted[0].strip(), rule_id,rule_msg,priotity,service,source_ip,source_port,target_ip,target_port,hash_diff)
	print(val)
	return val

def main():
  with open("C:/Users/i0220/taller-investigacion/python-pipeline/snort2.alert.fast", "r") as f:
			for line in f:
				try:
					sql = "INSERT INTO t_snort_log (process_date,timestamp,rule_id,rule_msg,priotity,service,source_ip,source_port,target_ip,target_port,hash_diff) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
					val = transform(line)
					mycursor.execute(sql, val)

					mydb.commit()
				
					print(mycursor.rowcount, "record inserted.")
				except:
					print(mycursor.rowcount, "record duplicated.")
if __name__ == '__main__':
  main()