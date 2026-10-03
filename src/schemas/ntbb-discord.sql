CREATE TABLE `ntbb_discord` (
	discordid varchar(20) NOT NULL PRIMARY KEY,
	userid varchar(18) NOT NULL,
	time BIGINT(20) NOT NULL,
	UNIQUE KEY `userid` (`userid`)
);
