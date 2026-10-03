CREATE TABLE `ntbb_discord` (
	userid varchar(18) NOT NULL PRIMARY KEY,
	discordid varchar(20) NOT NULL,
	time BIGINT(20) NOT NULL,
	KEY `discordid` (`discordid`)
);
