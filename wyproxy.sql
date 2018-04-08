/*
 Navicat Premium Data Transfer

 Source Server         : localhost
 Source Server Type    : MySQL
 Source Server Version : 50621
 Source Host           : localhost
 Source Database       : wyproxy

 Target Server Type    : MySQL
 Target Server Version : 50621
 File Encoding         : utf-8

 Date: 09/13/2016 12:22:26 PM
*/

CREATE DATABASE IF NOT EXISTS `wyproxy` DEFAULT CHARSET utf8 COLLATE utf8_general_ci;

USE `wyproxy`;

SET NAMES utf8;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
--  Table structure for `capture`
-- ----------------------------
DROP TABLE IF EXISTS `capture`;
CREATE TABLE `capture` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `method` char(10) DEFAULT NULL,
  `status_code` int(6) DEFAULT NULL,
  `host` varchar(255) DEFAULT NULL,
  `url` text,
  `path` text,
  `request_header` mediumtext,
  `request_content` mediumblob,
  `date_time` datetime DEFAULT NULL,
  `extension` char(32) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

/* SET FOREIGN_KEY_CHECKS = 1; */

CREATE TABLE `vulns` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `method` char(10) DEFAULT NULL,
  `proof` varchar(255) DEFAULT NULL,
  `checks` varchar(255) DEFAULT NULL,
  `url` text,
  `severity` varchar(25),
  `headers_string` mediumtext,
  `parameters` mediumtext,
  `delta_time` varchar(50) DEFAULT NULL,
  `vuln_name` varchar(32) DEFAULT NULL,
  `seed` varchar(100) DEFAULT NULL,

  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

SET FOREIGN_KEY_CHECKS = 1;
