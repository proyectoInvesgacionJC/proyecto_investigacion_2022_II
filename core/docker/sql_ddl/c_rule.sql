use snort;
CREATE TABLE `c_rule` (
  `rule_id` varchar(250) DEFAULT NULL,
  `rule_name` varchar(250) DEFAULT NULL,
  `rule_description` varchar(250) DEFAULT NULL,
  `creation_user` varchar(250) DEFAULT NULL,
  `load_date` timestamp
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO `snort`.`c_rule`
(`rule_id`,
`rule_name`,
`rule_description`,
`creation_user`,
`load_date`)
VALUES ('10000','SSH TRAFFIC','Incomming SSH traffic',
USER(),CURRENT_TIMESTAMP())
,('10001','SSH FORCE BRUTE','Scan SSH brute force login attempt',
USER(),CURRENT_TIMESTAMP())
,('10002','TERRORISM','Harmful content seach',
USER(),CURRENT_TIMESTAMP())
,('10003','TERRORISM','Harmful content seach',
USER(),CURRENT_TIMESTAMP())
,('10004','PORN', 'Harmful content seach',
USER(),CURRENT_TIMESTAMP())
,('10005','PORN', 'Harmful content seach',
USER(),CURRENT_TIMESTAMP())
,('10006','FTP CONNECTION', 'Incoming FTP connection',
USER(),CURRENT_TIMESTAMP())
,('10007','TORRENT TRAFFIC', 'Torrent-TCP Traffic in the port 6881',
USER(),CURRENT_TIMESTAMP());