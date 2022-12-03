use snort;
CREATE TABLE `t_snort_log` (
  `process_date` DATE NOT NULL,
  `timestamp` varchar(250) DEFAULT NULL,
  `rule_id` varchar(250) DEFAULT NULL,
  `rule_msg` varchar(250) DEFAULT NULL,
  `priotity` varchar(250) DEFAULT NULL,
  `service` varchar(250) DEFAULT NULL,
  `source_ip` varchar(250) DEFAULT NULL,
  `source_port` varchar(250) DEFAULT NULL,
  `target_ip` varchar(250) DEFAULT NULL,
  `target_port` varchar(250) DEFAULT NULL,
  `hash_diff` varchar(500) NOT NULL,
  PRIMARY KEY(hash_diff)
);
