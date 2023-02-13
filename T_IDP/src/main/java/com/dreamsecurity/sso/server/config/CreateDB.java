package com.dreamsecurity.sso.server.config;

import java.io.Console;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Scanner;

public class CreateDB
{
	public static void createSequence(String dbDriver, String dburl, String dbusr, String dbpwd) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP SEQUENCE SEQ_SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 2289) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE SEQUENCE SEQ_SSO_ACLG ")
				.append("START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 99999999 NOCYCLE NOCACHE ORDER ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query03 = new StringBuffer();
			query03.append("DROP SEQUENCE SEQ_SSO_AULG ");

			pstmt = conn.prepareStatement(query03.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 2289) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query04 = new StringBuffer();
		query04.append("CREATE SEQUENCE SEQ_SSO_AULG ")
				.append("START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 99999999 NOCYCLE NOCACHE ORDER ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		conn.close();
	}

	// Cubrid
	public static void createSequence_cubrid(String dbDriver, String dburl, String dbusr, String dbpwd) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP SERIAL SEQ_SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -773) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE SERIAL SEQ_SSO_ACLG ")
				.append("START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 99999999 NOCYCLE NOCACHE ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query03 = new StringBuffer();
			query03.append("DROP SERIAL SEQ_SSO_AULG ");

			pstmt = conn.prepareStatement(query03.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -773) {
				throw new Exception(e.getMessage());
			}

			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query04 = new StringBuffer();
		query04.append("CREATE SERIAL SEQ_SSO_AULG ")
				.append("START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 99999999 NOCYCLE NOCACHE ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	// PostgreSQL
	public static void createSequence_postgresql(String dbDriver, String dburl, String dbusr, String dbpwd) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP SEQUENCE SEQ_SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE SEQUENCE SEQ_SSO_ACLG ")
				.append("INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 99999999 CACHE 1 ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query03 = new StringBuffer();
			query03.append("DROP SEQUENCE SEQ_SSO_AULG ");

			pstmt = conn.prepareStatement(query03.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query04 = new StringBuffer();
		query04.append("CREATE SEQUENCE SEQ_SSO_AULG ")
				.append("INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 99999999 CACHE 1 ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		conn.close();
	}

	// MySQL
	public static void createSequence_mysql(String dbDriver, String dburl, String dbusr, String dbpwd) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_SEQ ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_SEQ      ")
			.append(" (                           ")
			.append("   SEQ_NAME      VARCHAR(100)        NOT NULL,                    ")
			.append("   SEQ_INCREMENT INT(11) UNSIGNED    NOT NULL DEFAULT '1',        ")
			.append("   SEQ_MINVALUE  INT(11) UNSIGNED    NOT NULL DEFAULT '1',        ")
			.append("   SEQ_MAXVALUE  BIGINT(20) UNSIGNED NOT NULL DEFAULT '99999999', ")
			.append("   SEQ_CURVALUE  BIGINT(20) UNSIGNED NULL DEFAULT '1',            ")
			.append("   SEQ_CYCLE     TINYINT(1)          NOT NULL DEFAULT FALSE,      ")
			.append("   CONSTRAINT IDX_SSO_SEQ_PK ")
			.append("     PRIMARY KEY (SEQ_NAME)  ")
			.append(" )                           ")
			.append(" COLLATE='utf8_general_ci'   ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query03 = new StringBuffer();
		query03.append("INSERT INTO SSO_SEQ(SEQ_NAME, SEQ_CYCLE) VALUES ('SEQ_SSO_AULG', TRUE) ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		StringBuffer query04 = new StringBuffer();
		query04.append("INSERT INTO SSO_SEQ(SEQ_NAME, SEQ_CYCLE) VALUES ('SEQ_SSO_ACLG', TRUE) ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query06 = new StringBuffer();
			query06.append("DROP FUNCTION NEXTVAL ");

			pstmt = conn.prepareStatement(query06.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1305) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query05 = new StringBuffer();
		query05.append("CREATE FUNCTION NEXTVAL(name varchar(100))                      \n")
			.append("RETURNS BIGINT UNSIGNED                                         \n")
			.append("MODIFIES SQL DATA                                               \n")
			.append("DETERMINISTIC                                                   \n")
			.append("BEGIN                                                           \n")
			.append("    DECLARE cur_val BIGINT UNSIGNED;                            \n")
			.append("                                                                \n")
			.append("    SELECT seq_curvalue INTO cur_val                            \n")
			.append("    FROM   SSO_SEQ                                              \n")
			.append("    WHERE  seq_name = name;                                     \n")
			.append("                                                                \n")
			.append("    IF cur_val IS NOT NULL THEN                                 \n")
			.append("        UPDATE SSO_SEQ                                          \n")
			.append("        SET    seq_curvalue = IF (                              \n")
			.append("                 (seq_curvalue + seq_increment) > seq_maxvalue, \n")
			.append("                 IF (seq_cycle = TRUE, seq_minvalue, NULL),     \n")
			.append("                 seq_curvalue + seq_increment                   \n")
			.append("               )                                                \n")
			.append("        WHERE  seq_name = name;                                 \n")
			.append("    END IF;                                                     \n")
			.append("                                                                \n")
			.append("    RETURN cur_val;                                             \n")
			.append("END                                                             ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		conn.close();
	}

	// SQL Server
	public static void createSequence_sqlserver(String dbDriver, String dburl, String dbusr, String dbpwd) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP SEQUENCE SEQ_SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE SEQUENCE SEQ_SSO_ACLG ")
				.append("START WITH 1 MINVALUE 1 MAXVALUE 99999999 NO CYCLE NO CACHE ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query03 = new StringBuffer();
			query03.append("DROP SEQUENCE SEQ_SSO_AULG ");

			pstmt = conn.prepareStatement(query03.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query04 = new StringBuffer();
		query04.append("CREATE SEQUENCE SEQ_SSO_AULG ")
				.append("START WITH 1 MINVALUE 1 MAXVALUE 99999999 NO CYCLE NO CACHE ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		conn.close();
	}

	public static void createSequence_tibero(String dbDriver, String dburl, String dbusr, String dbpwd) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP SEQUENCE SEQ_SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE SEQUENCE SEQ_SSO_ACLG ")
				.append("START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 99999999 NOCYCLE NOCACHE ORDER ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query03 = new StringBuffer();
			query03.append("DROP SEQUENCE SEQ_SSO_AULG ");

			pstmt = conn.prepareStatement(query03.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query04 = new StringBuffer();
		query04.append("CREATE SEQUENCE SEQ_SSO_AULG ")
				.append("START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 99999999 NOCYCLE NOCACHE ORDER ");

		pstmt = conn.prepareStatement(query04.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		conn.close();
	}

	public static void createTableIndex(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		String tablespace = "";
		if (!dbtsp.isEmpty()) {
			tablespace = " TABLESPACE " + dbtsp;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                      ")
			.append("   LOG_DATE     VARCHAR2(8 BYTE),       ")
			.append("   LOG_TIME     VARCHAR2(6 BYTE),       ")
			.append("   SEQ          VARCHAR2(8 BYTE),       ")
			.append("   USER_ID      VARCHAR2(100 BYTE),     ")
			.append("   USER_NAME    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_IP    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_TYPE  VARCHAR2(2 BYTE),       ")
			.append("   ACCESS_SP    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_BR    VARCHAR2(2 BYTE),       ")
			.append("   ACCESS_RSLT  VARCHAR2(2 BYTE)        ")
			.append(" )                                      ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		StringBuffer query03 = new StringBuffer();
		query03.append("ALTER TABLE SSO_ACLG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ACLG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query04 = new StringBuffer();
			query04.append("DROP TABLE SSO_ADIP ");

			pstmt = conn.prepareStatement(query04.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query05 = new StringBuffer();
		query05.append("CREATE TABLE SSO_ADIP ")
			.append(" (                                      ")
			.append("   IP  VARCHAR2(256 BYTE)               ")
			.append(" )                                      ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query06 = new StringBuffer();
		query06.append("ALTER TABLE SSO_ADIP ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ADIP_PK             ")
			.append(" PRIMARY KEY (IP)                       ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query06.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query07 = new StringBuffer();
			query07.append("DROP TABLE SSO_ADMN ");

			pstmt = conn.prepareStatement(query07.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query08 = new StringBuffer();
		query08.append("CREATE TABLE SSO_ADMN ")
			.append(" (                                        ")
			.append("   ID                 VARCHAR2(100 BYTE), ")
			.append("   NAME               VARCHAR2(100 BYTE), ")
			.append("   PASSWORD           VARCHAR2(256 BYTE), ")
			.append("   STATUS             VARCHAR2(1 BYTE),   ")
			.append("   ADPY_CODE          VARCHAR2(20 BYTE),  ")
			.append("   PW_MISMATCH_COUNT  VARCHAR2(8 BYTE),   ")
			.append("   PW_UPDATE_TIME     DATE,               ")
			.append("   ADMN_TYPE          VARCHAR2(1 BYTE),   ")
			.append("   EMAIL              VARCHAR2(100 BYTE), ")
			.append("   MENU_CODE          VARCHAR2(256 BYTE), ")
			.append("   LOCK_TIME          DATE,               ")
			.append("   FIRST_YN           VARCHAR2(1 BYTE),   ")
			.append("   USE_YN             VARCHAR2(1 BYTE),   ")
			.append("   LOGIN_IP           VARCHAR2(100 BYTE), ")
			.append("   LOGIN_BR           VARCHAR2(2 BYTE),   ")
			.append("   LOGIN_TIME         DATE,               ")
			.append("   ACCESS_TIME        DATE                ")
			.append(" )                                        ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query08.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query09 = new StringBuffer();
		query09.append("ALTER TABLE SSO_ADMN ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ADMN_PK             ")
			.append(" PRIMARY KEY (ID)                       ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query09.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query10 = new StringBuffer();
			query10.append("DROP TABLE SSO_ADPY ");

			pstmt = conn.prepareStatement(query10.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query11 = new StringBuffer();
		query11.append("CREATE TABLE SSO_ADPY ")
			.append(" (                                        ")
			.append("   ADPY_CODE          VARCHAR2(20 BYTE),  ")
			.append("   NAME               VARCHAR2(100 BYTE), ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR2(256 BYTE), ")
			.append("   SESSION_TIME       VARCHAR2(256 BYTE), ")
			.append("   LOCK_TIME          VARCHAR2(256 BYTE), ")
			.append("   IP_MAX_COUNT       VARCHAR2(256 BYTE)  ")
			.append(" )                                        ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query12 = new StringBuffer();
		query12.append("ALTER TABLE SSO_ADPY ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ADPY_PK             ")
			.append(" PRIMARY KEY (ADPY_CODE)                ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query12.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                               ")
			.append("   LOG_DATE   VARCHAR2(8 BYTE),  ")
			.append("   LOG_TIME   VARCHAR2(6 BYTE),  ")
			.append("   SEQ        VARCHAR2(8 BYTE),  ")
			.append("   CASE_TYPE  VARCHAR2(2 BYTE),  ")
			.append("   CASE_RSLT  VARCHAR2(2 BYTE),  ")
			.append("   CASE_USER  VARCHAR2(30 BYTE), ")
			.append("   CASE_DATA  VARCHAR2(500 BYTE) ")
			.append(" )                               ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query15 = new StringBuffer();
		query15.append("ALTER TABLE SSO_AULG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_AULG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query16 = new StringBuffer();
			query16.append("DROP TABLE SSO_AUPY ");

			pstmt = conn.prepareStatement(query16.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query17 = new StringBuffer();
		query17.append("CREATE TABLE SSO_AUPY ")
			.append(" (                                   ")
			.append("   CODE          VARCHAR2(8 BYTE),   ")
			.append("   WARN_LIMIT    VARCHAR2(256 BYTE), ")
			.append("   VERIFY_CYCLE  VARCHAR2(256 BYTE), ")
			.append("   VERIFY_POINT  VARCHAR2(256 BYTE), ")
			.append("   VERIFY_TIME   DATE                ")
			.append(" )                                   ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query18 = new StringBuffer();
		query18.append("ALTER TABLE SSO_AUPY ADD ( ")
			.append(" CONSTRAINT IDX_SSO_AUPY_PK             ")
			.append(" PRIMARY KEY (CODE)                     ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query18.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query19 = new StringBuffer();
			query19.append("DROP TABLE SSO_CERT ");

			pstmt = conn.prepareStatement(query19.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query20 = new StringBuffer();
		query20.append("CREATE TABLE SSO_CERT ")
			.append(" (                                 ")
			.append("   DN          VARCHAR2(256 BYTE), ")
			.append("   ISSUE_DATE  DATE,               ")
			.append("   REVOC_DATE  DATE,               ")
			.append("   STATUS      VARCHAR2(1 BYTE),   ")
			.append("   CERT_FILE   VARCHAR2(256 BYTE)  ")
			.append(" )                                 ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query21 = new StringBuffer();
		query21.append("ALTER TABLE SSO_CERT ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CERT_PK             ")
			.append(" PRIMARY KEY (DN, ISSUE_DATE)           ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query21.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query22 = new StringBuffer();
			query22.append("DROP TABLE SSO_IPLG ");

			pstmt = conn.prepareStatement(query22.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query23 = new StringBuffer();
		query23.append("CREATE TABLE SSO_IPLG ")
			.append(" (                                 ")
			.append("   IP          VARCHAR2(100 BYTE), ")
			.append("   LOGIN_ID    VARCHAR2(100 BYTE), ")
			.append("   LOGIN_BR    VARCHAR2(2 BYTE),   ")
			.append("   LOGIN_TIME  DATE                ")
			.append(" )                                 ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query23.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query24 = new StringBuffer();
		query24.append("ALTER TABLE SSO_IPLG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_IPLG_PK             ")
			.append(" PRIMARY KEY (IP)                       ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query24.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query25 = new StringBuffer();
			query25.append("DROP TABLE SSO_MSND ");

			pstmt = conn.prepareStatement(query25.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query26 = new StringBuffer();
		query26.append("CREATE TABLE SSO_MSND ")
			.append(" (                               ")
			.append("   CODE      VARCHAR2(8 BYTE),   ")
			.append("   REFERRER  VARCHAR2(512 BYTE), ")
			.append("   SUBJECT   VARCHAR2(512 BYTE), ")
			.append("   BODY      VARCHAR2(512 BYTE)  ")
			.append(" )                               ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query26.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query27 = new StringBuffer();
		query27.append("ALTER TABLE SSO_MSND ADD ( ")
			.append(" CONSTRAINT IDX_SSO_MSND_PK             ")
			.append(" PRIMARY KEY (CODE)                     ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query27.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query28 = new StringBuffer();
			query28.append("DROP TABLE SSO_MSVR ");

			pstmt = conn.prepareStatement(query28.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query29 = new StringBuffer();
		query29.append("CREATE TABLE SSO_MSVR ")
			.append(" (                                ")
			.append("   CODE       VARCHAR2(20 BYTE),  ")
			.append("   SMTP_HOST  VARCHAR2(256 BYTE), ")
			.append("   SMTP_PORT  VARCHAR2(256 BYTE), ")
			.append("   SMTP_CHNL  VARCHAR2(256 BYTE), ")
			.append("   SMTP_AUTH  VARCHAR2(256 BYTE), ")
			.append("   AUTH_ID    VARCHAR2(256 BYTE), ")
			.append("   AUTH_PW    VARCHAR2(256 BYTE)  ")
			.append(" )                                ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query29.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query30 = new StringBuffer();
		query30.append("ALTER TABLE SSO_MSVR ADD ( ")
			.append(" CONSTRAINT IDX_SSO_MSVR_PK             ")
			.append(" PRIMARY KEY (CODE)                     ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query30.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query31 = new StringBuffer();
			query31.append("DROP TABLE SSO_URPY ");

			pstmt = conn.prepareStatement(query31.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query32 = new StringBuffer();
		query32.append("CREATE TABLE SSO_URPY ")
			.append(" (                                        ")
			.append("   URPY_CODE          VARCHAR2(20 BYTE),  ")
			.append("   NAME               VARCHAR2(100 BYTE), ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR2(256 BYTE), ")
			.append("   PW_CHANGE_WARN     VARCHAR2(256 BYTE), ")
			.append("   PW_VALIDATE        VARCHAR2(256 BYTE), ")
			.append("   SESSION_TIME       VARCHAR2(256 BYTE), ")
			.append("   POLLING_TIME       VARCHAR2(256 BYTE)  ")
			.append(" )                                        ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query32.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query33 = new StringBuffer();
		query33.append("ALTER TABLE SSO_URPY ADD ( ")
			.append(" CONSTRAINT IDX_SSO_URPY_PK             ")
			.append(" PRIMARY KEY (URPY_CODE)                ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query33.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query34 = new StringBuffer();
			query34.append("DROP TABLE SSO_USER ");

			pstmt = conn.prepareStatement(query34.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query35 = new StringBuffer();
		query35.append("CREATE TABLE SSO_USER ")
			.append(" (                                        ")
			.append("   ID                 VARCHAR2(100 BYTE), ")
			.append("   NAME               VARCHAR2(100 BYTE), ")
			.append("   PASSWORD           VARCHAR2(256 BYTE), ")
			.append("   DN                 VARCHAR2(256 BYTE), ")
			.append("   STATUS             VARCHAR2(1 BYTE),   ")
			.append("   URPY_CODE          VARCHAR2(20 BYTE),  ")
			.append("   PW_MISMATCH_COUNT  VARCHAR2(8 BYTE),   ")
			.append("   PW_UPDATE_TIME     DATE,               ")
			.append("   LOGIN_IP           VARCHAR2(100 BYTE), ")
			.append("   LOGIN_BR           VARCHAR2(2 BYTE),   ")
			.append("   LOGIN_TIME         DATE,               ")
			.append("   LAST_LOGIN_IP      VARCHAR2(100 BYTE), ")
			.append("   LAST_LOGIN_TIME    DATE,               ")
			.append("   CS_LOGIN_TIME      DATE,               ")
			.append("   ACCESS_TIME        DATE,               ")
			.append("   EMAIL              VARCHAR2(100 BYTE), ")
			.append("   PHONE              VARCHAR2(100 BYTE), ")
			.append("   ADDRESS            VARCHAR2(100 BYTE)  ")
			.append(" )                                        ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query35.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query36 = new StringBuffer();
		query36.append("ALTER TABLE SSO_USER ADD ( ")
			.append(" CONSTRAINT IDX_SSO_USER_PK             ")
			.append(" PRIMARY KEY (ID)                       ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query36.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query00 = new StringBuffer();
			query00.append("DROP TABLE SSO_CLIENT ");

			pstmt = conn.prepareStatement(query00.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query37 = new StringBuffer();
		query37.append("CREATE TABLE SSO_CLIENT ")
			.append(" ( ")
			.append("   CLIENT                      VARCHAR2(100 BYTE), ")
			.append("   NAME               VARCHAR2(100 BYTE), ")
			.append("   ENABLED                 VARCHAR2(10 BYTE),  ")
			.append("   NONCE                   VARCHAR2(10 BYTE),  ")
			.append("   PKCE                    VARCHAR2(10 BYTE),  ")
			.append("   REFRESH_TOKEN_USE       VARCHAR2(10 BYTE),  ")
			.append("   SECRET                  VARCHAR2(100 BYTE), ")
			.append("   TOKEN_LIFESPAN          VARCHAR2(10 BYTE),  ")
			.append("   CODE_LIFESPAN           VARCHAR2(10 BYTE),  ")
			.append("   REFRESH_TOKEN_LIFESPAN  VARCHAR2(10 BYTE),  ")
			.append("   RESPONSE_TYPE           VARCHAR2(10 BYTE),  ")
			.append("   GRANT_TYPE              VARCHAR2(30 BYTE),  ")
			.append("   PROTOCOL                VARCHAR2(10 BYTE)   ")
			.append(" ) ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query37.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query38 = new StringBuffer();
		query38.append("ALTER TABLE SSO_CLIENT ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CLIENT_PK      ")
			.append(" PRIMARY KEY (CLIENT)                       ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query38.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query00 = new StringBuffer();
			query00.append("DROP TABLE SSO_CLIENT_SCOPE ");

			pstmt = conn.prepareStatement(query00.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query39 = new StringBuffer();
		query39.append("CREATE TABLE SSO_CLIENT_SCOPE ")
			.append(" ( ")
			.append("   SCOPE   VARCHAR2(100 BYTE), ")
			.append("   CLIENT  VARCHAR2(100 BYTE)  ")
			.append(" ) ")
			.append(tablespace)
			.append(" PCTUSED    0   ")
			.append(" PCTFREE    10  ")
			.append(" INITRANS   1   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING    ")
			.append(" NOCOMPRESS ")
			.append(" NOCACHE    ")
			.append(" NOPARALLEL ")
			.append(" MONITORING ");

		pstmt = conn.prepareStatement(query39.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query40 = new StringBuffer();
		query40.append("ALTER TABLE SSO_CLIENT_SCOPE ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CLIENT_SCOPE_PK ")
			.append(" PRIMARY KEY (SCOPE, CLIENT)  ")
			.append(" USING INDEX ")
			.append(tablespace)
			.append(" PCTFREE    10  ")
			.append(" INITRANS   2   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query40.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query41 = new StringBuffer();
		query41.append("CREATE INDEX IDX_SSO_CLIENT_SCOPE_01 ")
			.append(" ON SSO_CLIENT_SCOPE(CLIENT) ")
			.append(" LOGGING ")
			.append(tablespace)
			.append(" PCTFREE    10  ")
			.append(" INITRANS   2   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ) ")
			.append(" NOPARALLEL ");

		pstmt = conn.prepareStatement(query41.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query00 = new StringBuffer();
			query00.append("DROP TABLE SSO_CLIENT_REDIRECT ");

			pstmt = conn.prepareStatement(query00.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query42 = new StringBuffer();
		query42.append("CREATE TABLE SSO_CLIENT_REDIRECT ")
			.append(" ( ")
			.append("   CLIENT     VARCHAR2(100 BYTE), ")
			.append("   REDIRECT_URI  VARCHAR2(200 BYTE)  ")
			.append(" ) ")
			.append(tablespace)
			.append(" PCTUSED    0   ")
			.append(" PCTFREE    10  ")
			.append(" INITRANS   1   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING    ")
			.append(" NOCOMPRESS ")
			.append(" NOCACHE    ")
			.append(" NOPARALLEL ")
			.append(" MONITORING ");

		pstmt = conn.prepareStatement(query42.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query43 = new StringBuffer();
		query43.append("ALTER TABLE SSO_CLIENT_REDIRECT ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CLIENT_REDIRECT_PK ")
			.append(" PRIMARY KEY (CLIENT, REDIRECT_URI)  ")
			.append(" USING INDEX ")
			.append(tablespace)
			.append(" PCTFREE    10  ")
			.append(" INITRANS   2   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query43.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query00 = new StringBuffer();
			query00.append("DROP TABLE SSO_SCOPES ");

			pstmt = conn.prepareStatement(query00.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query44 = new StringBuffer();
		query44.append("CREATE TABLE SSO_SCOPES ")
			.append(" ( ")
			.append("   SCOPE  VARCHAR2(100 BYTE)  ")
			.append(" ) ")
			.append(tablespace)
			.append(" PCTUSED    0   ")
			.append(" PCTFREE    10  ")
			.append(" INITRANS   1   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING    ")
			.append(" NOCOMPRESS ")
			.append(" NOCACHE    ")
			.append(" NOPARALLEL ")
			.append(" MONITORING ");

		pstmt = conn.prepareStatement(query44.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query45 = new StringBuffer();
		query45.append("ALTER TABLE SSO_SCOPES ADD ( ")
			.append(" CONSTRAINT IDX_SSO_SCOPES_PK ")
			.append(" PRIMARY KEY (SCOPE) ")
			.append(" USING INDEX ")
			.append(tablespace)
			.append(" PCTFREE    10  ")
			.append(" INITRANS   2   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query45.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	// Cubrid
	public static void createTableIndex_cubrid(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                      ")
			.append("   LOG_DATE     VARCHAR(8),       		 ")
			.append("   LOG_TIME     VARCHAR(6),       	 	 ")
			.append("   SEQ          VARCHAR(8),       		 ")
			.append("   USER_ID      VARCHAR(100),     		 ")
			.append("   USER_NAME    VARCHAR(100),     		 ")
			.append("   ACCESS_IP    VARCHAR(100),     		 ")
			.append("   ACCESS_TYPE  VARCHAR(2),       		 ")
			.append("   ACCESS_SP    VARCHAR(100),     		 ")
			.append("   ACCESS_BR    VARCHAR(2),       		 ")
			.append("   ACCESS_RSLT  VARCHAR(2)        		 ")
			.append(" )                                      ");
			
		
		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();		
		pstmt.close();
		pstmt = null;
		
		StringBuffer query03 = new StringBuffer();
		query03.append("ALTER TABLE SSO_ACLG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ACLG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		try {
			StringBuffer query04 = new StringBuffer();
			query04.append("DROP TABLE SSO_ADIP ");

			pstmt = conn.prepareStatement(query04.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}

			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}

		StringBuffer query05 = new StringBuffer();
		query05.append("CREATE TABLE SSO_ADIP ")
			.append(" (                                      ")
			.append("   IP  VARCHAR(256)               	 	 ")
			.append(" )                                      ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query06 = new StringBuffer();
		query06.append("ALTER TABLE SSO_ADIP ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ADIP_PK             ")
			.append(" PRIMARY KEY (IP)                       ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query06.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query07 = new StringBuffer();
			query07.append("DROP TABLE SSO_ADMN ");

			pstmt = conn.prepareStatement(query07.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}

			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query08 = new StringBuffer();
		query08.append("CREATE TABLE SSO_ADMN ")
			.append(" (                                        ")
			.append("   ID                 VARCHAR(100), 	   ")
			.append("   NAME               VARCHAR(100), 	   ")
			.append("   PASSWORD           VARCHAR(256), 	   ")
			.append("   STATUS             VARCHAR(1),   	   ")
			.append("   ADPY_CODE          VARCHAR(20),  	   ")
			.append("   PW_MISMATCH_COUNT  VARCHAR(8),   	   ")
			.append("   PW_UPDATE_TIME     DATETIME,           ")
			.append("   ADMN_TYPE          VARCHAR(1),   	   ")
			.append("   EMAIL              VARCHAR(100), 	   ")
			.append("   MENU_CODE          VARCHAR(256), 	   ")
			.append("   LOCK_TIME          DATETIME,           ")
			.append("   FIRST_YN           VARCHAR(1),   	   ")
			.append("   USE_YN             VARCHAR(1),   	   ")
			.append("   LOGIN_IP           VARCHAR(100), 	   ")
			.append("   LOGIN_BR           VARCHAR(2),   	   ")
			.append("   LOGIN_TIME         DATETIME,           ")
			.append("   ACCESS_TIME        DATETIME            ")
			.append(" )                                        ");


		pstmt = conn.prepareStatement(query08.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query09 = new StringBuffer();
		query09.append("ALTER TABLE SSO_ADMN ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ADMN_PK             ")
			.append(" PRIMARY KEY (ID)                       ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query09.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query10 = new StringBuffer();
			query10.append("DROP TABLE SSO_ADPY ");

			pstmt = conn.prepareStatement(query10.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}

			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query11 = new StringBuffer();
		query11.append("CREATE TABLE SSO_ADPY ")
			.append(" (                                        ")
			.append("   ADPY_CODE          VARCHAR(20),  	   ")
			.append("   NAME               VARCHAR(100), 	   ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR(256), 	   ")
			.append("   SESSION_TIME       VARCHAR(256), 	   ")
			.append("   LOCK_TIME          VARCHAR(256), 	   ")
			.append("   IP_MAX_COUNT       VARCHAR(256)  	   ")
			.append(" )                                        ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query12 = new StringBuffer();
		query12.append("ALTER TABLE SSO_ADPY ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ADPY_PK             ")
			.append(" PRIMARY KEY (ADPY_CODE)                ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query12.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                               ")
			.append("   LOG_DATE   VARCHAR(8),  	  ")
			.append("   LOG_TIME   VARCHAR(6),  	  ")
			.append("   SEQ        VARCHAR(8),  	  ")
			.append("   CASE_TYPE  VARCHAR(2),  	  ")
			.append("   CASE_RSLT  VARCHAR(2),  	  ")
			.append("   CASE_USER  VARCHAR(30), 	  ")
			.append("   CASE_DATA  VARCHAR(500) 	  ")
			.append(" )                               ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query15 = new StringBuffer();
		query15.append("ALTER TABLE SSO_AULG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_AULG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query16 = new StringBuffer();
			query16.append("DROP TABLE SSO_AUPY ");

			pstmt = conn.prepareStatement(query16.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query17 = new StringBuffer();
		query17.append("CREATE TABLE SSO_AUPY ")
			.append(" (                                   ")
			.append("   CODE          VARCHAR(8),   	  ")
			.append("   WARN_LIMIT    VARCHAR(256), 	  ")
			.append("   VERIFY_CYCLE  VARCHAR(256), 	  ")
			.append("   VERIFY_POINT  VARCHAR(256), 	  ")
			.append("   VERIFY_TIME   DATETIME            ")
			.append(" )                                   ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query18 = new StringBuffer();
		query18.append("ALTER TABLE SSO_AUPY ADD ( ")
			.append(" CONSTRAINT IDX_SSO_AUPY_PK             ")
			.append(" PRIMARY KEY (CODE)                     ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query18.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query19 = new StringBuffer();
			query19.append("DROP TABLE SSO_CERT ");

			pstmt = conn.prepareStatement(query19.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query20 = new StringBuffer();
		query20.append("CREATE TABLE SSO_CERT ")
			.append(" (                                 ")
			.append("   DN          VARCHAR(256), 		")
			.append("   ISSUE_DATE  DATETIME,           ")
			.append("   REVOC_DATE  DATETIME,           ")
			.append("   STATUS      VARCHAR(1),   		")
			.append("   CERT_FILE   VARCHAR(256)  		")
			.append(" )                                 ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query21 = new StringBuffer();
		query21.append("ALTER TABLE SSO_CERT ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CERT_PK             ")
			.append(" PRIMARY KEY (DN, ISSUE_DATE)           ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query21.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query22 = new StringBuffer();
			query22.append("DROP TABLE SSO_IPLG ");

			pstmt = conn.prepareStatement(query22.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query23 = new StringBuffer();
		query23.append("CREATE TABLE SSO_IPLG ")
			.append(" (                                 ")
			.append("   IP          VARCHAR(100), 		")
			.append("   LOGIN_ID    VARCHAR(100), 		")
			.append("   LOGIN_BR    VARCHAR(2),   		")
			.append("   LOGIN_TIME  DATETIME            ")
			.append(" )                                 ");

		pstmt = conn.prepareStatement(query23.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query24 = new StringBuffer();
		query24.append("ALTER TABLE SSO_IPLG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_IPLG_PK             ")
			.append(" PRIMARY KEY (IP)                       ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query24.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query25 = new StringBuffer();
			query25.append("DROP TABLE SSO_MSND ");

			pstmt = conn.prepareStatement(query25.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query26 = new StringBuffer();
		query26.append("CREATE TABLE SSO_MSND ")
			.append(" (                               ")
			.append("   CODE      VARCHAR(8),   	  ")
			.append("   REFERRER  VARCHAR(512), 	  ")
			.append("   SUBJECT   VARCHAR(512), 	  ")
			.append("   BODY      VARCHAR(512)  	  ")
			.append(" )                               ");

		pstmt = conn.prepareStatement(query26.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query27 = new StringBuffer();
		query27.append("ALTER TABLE SSO_MSND ADD ( ")
			.append(" CONSTRAINT IDX_SSO_MSND_PK             ")
			.append(" PRIMARY KEY (CODE)                     ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query27.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query28 = new StringBuffer();
			query28.append("DROP TABLE SSO_MSVR ");

			pstmt = conn.prepareStatement(query28.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query29 = new StringBuffer();
		query29.append("CREATE TABLE SSO_MSVR ")
			.append(" (                                ")
			.append("   CODE       VARCHAR(20),  	   ")
			.append("   SMTP_HOST  VARCHAR(256), 	   ")
			.append("   SMTP_PORT  VARCHAR(256), 	   ")
			.append("   SMTP_CHNL  VARCHAR(256), 	   ")
			.append("   SMTP_AUTH  VARCHAR(256), 	   ")
			.append("   AUTH_ID    VARCHAR(256), 	   ")
			.append("   AUTH_PW    VARCHAR(256)  	   ")
			.append(" )                                ");

		pstmt = conn.prepareStatement(query29.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query30 = new StringBuffer();
		query30.append("ALTER TABLE SSO_MSVR ADD ( ")
			.append(" CONSTRAINT IDX_SSO_MSVR_PK             ")
			.append(" PRIMARY KEY (CODE)                     ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query30.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query31 = new StringBuffer();
			query31.append("DROP TABLE SSO_URPY ");

			pstmt = conn.prepareStatement(query31.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query32 = new StringBuffer();
		query32.append("CREATE TABLE SSO_URPY ")
			.append(" (                                        ")
			.append("   URPY_CODE          VARCHAR(20),  	   ")
			.append("   NAME               VARCHAR(100), 	   ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR(256), 	   ")
			.append("   PW_CHANGE_WARN     VARCHAR(256), 	   ")
			.append("   PW_VALIDATE        VARCHAR(256), 	   ")
			.append("   SESSION_TIME       VARCHAR(256), 	   ")
			.append("   POLLING_TIME       VARCHAR(256)  	   ")
			.append(" )                                        ");

		pstmt = conn.prepareStatement(query32.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query33 = new StringBuffer();
		query33.append("ALTER TABLE SSO_URPY ADD ( ")
			.append(" CONSTRAINT IDX_SSO_URPY_PK             ")
			.append(" PRIMARY KEY (URPY_CODE)                ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query33.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query34 = new StringBuffer();
			query34.append("DROP TABLE SSO_USER ");

			pstmt = conn.prepareStatement(query34.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}
		StringBuffer query35 = new StringBuffer();
		query35.append("CREATE TABLE SSO_USER ")
			.append(" (                                        ")
			.append("   ID                 VARCHAR(100), 	   ")
			.append("   NAME               VARCHAR(100), 	   ")
			.append("   PASSWORD           VARCHAR(256), 	   ")
			.append("   DN                 VARCHAR(256), 	   ")
			.append("   STATUS             VARCHAR(1),   	   ")
			.append("   URPY_CODE          VARCHAR(20),  	   ")
			.append("   PW_MISMATCH_COUNT  VARCHAR(8),   	   ")
			.append("   PW_UPDATE_TIME     DATETIME,           ")
			.append("   LOGIN_IP           VARCHAR(100), 	   ")
			.append("   LOGIN_BR           VARCHAR(2),   	   ")
			.append("   LOGIN_TIME         DATETIME,           ")
			.append("   LAST_LOGIN_IP      VARCHAR(100), 	   ")
			.append("   LAST_LOGIN_TIME    DATETIME,           ")
			.append("   CS_LOGIN_TIME      DATETIME,           ")
			.append("   ACCESS_TIME        DATETIME,           ")
			.append("   EMAIL              VARCHAR(100),       ")
			.append("   PHONE              VARCHAR(100),       ")
			.append("   ADDRESS            VARCHAR(100)        ")
			.append(" )                                        ");

		pstmt = conn.prepareStatement(query35.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query36 = new StringBuffer();
		query36.append("ALTER TABLE SSO_USER ADD ( ")
			.append(" CONSTRAINT IDX_SSO_USER_PK             ")
			.append(" PRIMARY KEY (ID)                       ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query36.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}

		StringBuffer query37 = new StringBuffer();
		query37.append("CREATE TABLE SSO_CLIENT ")
			.append(" ( ")
			.append("   CLIENT                      VARCHAR(100), ")
			.append("   NAME               VARCHAR(100), ")
			.append("   ENABLED                 VARCHAR(10),  ")
			.append("   NONCE                   VARCHAR(10),  ")
			.append("   PKCE                    VARCHAR(10),  ")
			.append("   REFRESH_TOKEN_USE       VARCHAR(10),  ")
			.append("   SECRET                  VARCHAR(100), ")
			.append("   TOKEN_LIFESPAN          VARCHAR(10),  ")
			.append("   CODE_LIFESPAN           VARCHAR(10),  ")
			.append("   REFRESH_TOKEN_LIFESPAN  VARCHAR(10),  ")
			.append("   RESPONSE_TYPE           VARCHAR(10),  ")
			.append("   GRANT_TYPE              VARCHAR(30),  ")
			.append("   PROTOCOL                VARCHAR(10)   ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query37.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query38 = new StringBuffer();
		query38.append("ALTER TABLE SSO_CLIENT ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CLIENT_PK ")
			.append(" PRIMARY KEY (CLIENT) ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query38.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT_SCOPE ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}

		StringBuffer query39 = new StringBuffer();
		query39.append("CREATE TABLE SSO_CLIENT_SCOPE ")
			.append(" ( ")
			.append("   SCOPE   VARCHAR(100), ")
			.append("   CLIENT  VARCHAR(100)  ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query39.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query40 = new StringBuffer();
		query40.append("ALTER TABLE SSO_CLIENT_SCOPE ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CLIENT_SCOPE_PK ")
			.append(" PRIMARY KEY (SCOPE, CLIENT) ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query40.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query41 = new StringBuffer();
		query41.append("CREATE INDEX IDX_SSO_CLIENT_SCOPE_01 ")
		.append(" ON SSO_CLIENT_SCOPE(CLIENT) ");

		pstmt = conn.prepareStatement(query41.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT_REDIRECT ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}

		StringBuffer query42 = new StringBuffer();
		query42.append("CREATE TABLE SSO_CLIENT_REDIRECT ")
			.append(" ( ")
			.append("   CLIENT     VARCHAR(100), ")
			.append("   REDIRECT_URI  VARCHAR(200)  ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query42.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query43 = new StringBuffer();
		query43.append("ALTER TABLE SSO_CLIENT_REDIRECT ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CLIENT_REDIRECT_PK ")
			.append(" PRIMARY KEY (CLIENT, REDIRECT_URI) ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query43.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_SCOPES ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}

		StringBuffer query44 = new StringBuffer();
		query44.append("CREATE TABLE SSO_SCOPES ")
			.append(" ( ")
			.append("   SCOPE  VARCHAR(100)  ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query44.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query45 = new StringBuffer();
		query45.append("ALTER TABLE SSO_SCOPES ADD ( ")
			.append(" CONSTRAINT IDX_SSO_SCOPES_PK ")
			.append(" PRIMARY KEY (SCOPE) ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query45.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	// PostgreSQL
	public static void createTableIndex_postgresql(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                   ")
			.append("   LOG_DATE     VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME     VARCHAR(6) NOT NULL, ")
			.append("   SEQ          VARCHAR(8) NOT NULL, ")
			.append("   USER_ID      VARCHAR(100),        ")
			.append("   USER_NAME    VARCHAR(100),        ")
			.append("   ACCESS_IP    VARCHAR(100),        ")
			.append("   ACCESS_TYPE  VARCHAR(2),          ")
			.append("   ACCESS_SP    VARCHAR(100),        ")
			.append("   ACCESS_BR    VARCHAR(2),          ")
			.append("   ACCESS_RSLT  VARCHAR(2),          ")
			.append("   CONSTRAINT IDX_SSO_ACLG_PK        ")
			.append("     PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                         ")
			.append(" WITH ( OIDS = FALSE )                     ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		try {
			StringBuffer query04 = new StringBuffer();
			query04.append("DROP TABLE SSO_ADIP ");

			pstmt = conn.prepareStatement(query04.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query05 = new StringBuffer();
		query05.append("CREATE TABLE SSO_ADIP ")
			.append(" (                             ")
			.append("   IP  VARCHAR(256) NOT NULL,  ")
			.append("   CONSTRAINT IDX_SSO_ADIP_PK  ")
			.append("     PRIMARY KEY (IP)          ")
			.append(" )                             ")
			.append(" WITH ( OIDS = FALSE )         ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query07 = new StringBuffer();
			query07.append("DROP TABLE SSO_ADMN ");

			pstmt = conn.prepareStatement(query07.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query08 = new StringBuffer();
		query08.append("CREATE TABLE SSO_ADMN ")
			.append(" (                                  ")
			.append("   ID                 VARCHAR(100) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PASSWORD           VARCHAR(256), ")
			.append("   STATUS             VARCHAR(1),   ")
			.append("   ADPY_CODE          VARCHAR(20),  ")
			.append("   PW_MISMATCH_COUNT  VARCHAR(8),   ")
			.append("   PW_UPDATE_TIME     TIMESTAMP,    ")
			.append("   ADMN_TYPE          VARCHAR(1),   ")
			.append("   EMAIL              VARCHAR(100), ")
			.append("   MENU_CODE          VARCHAR(256), ")
			.append("   LOCK_TIME          TIMESTAMP,    ")
			.append("   FIRST_YN           VARCHAR(1),   ")
			.append("   USE_YN             VARCHAR(1),   ")
			.append("   LOGIN_IP           VARCHAR(100), ")
			.append("   LOGIN_BR           VARCHAR(2),   ")
			.append("   LOGIN_TIME         TIMESTAMP,    ")
			.append("   ACCESS_TIME        TIMESTAMP,    ")
			.append("   CONSTRAINT IDX_SSO_ADMN_PK       ")
			.append("   PRIMARY KEY (ID)                 ")
			.append(" )                                  ")
			.append(" WITH ( OIDS = FALSE )              ");

		pstmt = conn.prepareStatement(query08.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query10 = new StringBuffer();
			query10.append("DROP TABLE SSO_ADPY ");

			pstmt = conn.prepareStatement(query10.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query11 = new StringBuffer();
		query11.append("CREATE TABLE SSO_ADPY ")
			.append(" (                                  ")
			.append("   ADPY_CODE          VARCHAR(20) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR(256), ")
			.append("   SESSION_TIME       VARCHAR(256), ")
			.append("   LOCK_TIME          VARCHAR(256), ")
			.append("   IP_MAX_COUNT       VARCHAR(256), ")
			.append("   CONSTRAINT IDX_SSO_ADPY_PK       ")
			.append("   PRIMARY KEY (ADPY_CODE)          ")
			.append(" )                                  ")
			.append(" WITH ( OIDS = FALSE )              ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                                 ")
			.append("   LOG_DATE   VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME   VARCHAR(6) NOT NULL, ")
			.append("   SEQ        VARCHAR(8) NOT NULL, ")
			.append("   CASE_TYPE  VARCHAR(2),          ")
			.append("   CASE_RSLT  VARCHAR(2),          ")
			.append("   CASE_USER  VARCHAR(30),         ")
			.append("   CASE_DATA  VARCHAR(500),        ")
			.append("   CONSTRAINT IDX_SSO_AULG_PK            ")
			.append("   PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                       ")
			.append(" WITH ( OIDS = FALSE )                   ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query16 = new StringBuffer();
			query16.append("DROP TABLE SSO_AUPY ");

			pstmt = conn.prepareStatement(query16.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query17 = new StringBuffer();
		query17.append("CREATE TABLE SSO_AUPY ")
			.append(" (                             ")
			.append("   CODE          VARCHAR(8) NOT NULL, ")
			.append("   WARN_LIMIT    VARCHAR(256), ")
			.append("   VERIFY_CYCLE  VARCHAR(256), ")
			.append("   VERIFY_POINT  VARCHAR(256), ")
			.append("   VERIFY_TIME   TIMESTAMP,    ")
			.append("   CONSTRAINT IDX_SSO_AUPY_PK  ")
			.append("   PRIMARY KEY (CODE)          ")
			.append(" )                             ")
			.append(" WITH ( OIDS = FALSE )         ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query19 = new StringBuffer();
			query19.append("DROP TABLE SSO_CERT ");

			pstmt = conn.prepareStatement(query19.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query20 = new StringBuffer();
		query20.append("CREATE TABLE SSO_CERT ")
			.append(" (                              ")
			.append("   DN          VARCHAR(256) NOT NULL, ")
			.append("   ISSUE_DATE  DATE NOT NULL,   ")
			.append("   REVOC_DATE  TIMESTAMP,       ")
			.append("   STATUS      VARCHAR(1),      ")
			.append("   CERT_FILE   VARCHAR(256),    ")
			.append("   CONSTRAINT IDX_SSO_CERT_PK   ")
			.append("   PRIMARY KEY (DN, ISSUE_DATE) ")
			.append(" )                              ")
			.append(" WITH ( OIDS = FALSE )          ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query22 = new StringBuffer();
			query22.append("DROP TABLE SSO_IPLG ");

			pstmt = conn.prepareStatement(query22.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query23 = new StringBuffer();
		query23.append("CREATE TABLE SSO_IPLG ")
			.append(" (                            ")
			.append("   IP          VARCHAR(100) NOT NULL, ")
			.append("   LOGIN_ID    VARCHAR(100),  ")
			.append("   LOGIN_BR    VARCHAR(2),    ")
			.append("   LOGIN_TIME  TIMESTAMP,     ")
			.append("   CONSTRAINT IDX_SSO_IPLG_PK ")
			.append("   PRIMARY KEY (IP)           ")
			.append(" )                            ")
			.append(" WITH ( OIDS = FALSE )        ");

		pstmt = conn.prepareStatement(query23.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query25 = new StringBuffer();
			query25.append("DROP TABLE SSO_MSND ");

			pstmt = conn.prepareStatement(query25.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query26 = new StringBuffer();
		query26.append("CREATE TABLE SSO_MSND ")
			.append(" (                            ")
			.append("   CODE      VARCHAR(8) NOT NULL, ")
			.append("   REFERRER  VARCHAR(512),    ")
			.append("   SUBJECT   VARCHAR(512),    ")
			.append("   BODY      VARCHAR(512),    ")
			.append("   CONSTRAINT IDX_SSO_MSND_PK ")
			.append("   PRIMARY KEY (CODE)         ")
			.append(" )                            ")
			.append(" WITH ( OIDS = FALSE )        ");

		pstmt = conn.prepareStatement(query26.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query28 = new StringBuffer();
			query28.append("DROP TABLE SSO_MSVR ");

			pstmt = conn.prepareStatement(query28.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query29 = new StringBuffer();
		query29.append("CREATE TABLE SSO_MSVR ")
			.append(" (                            ")
			.append("   CODE       VARCHAR(20) NOT NULL, ")
			.append("   SMTP_HOST  VARCHAR(256),   ")
			.append("   SMTP_PORT  VARCHAR(256),   ")
			.append("   SMTP_CHNL  VARCHAR(256),   ")
			.append("   SMTP_AUTH  VARCHAR(256),   ")
			.append("   AUTH_ID    VARCHAR(256),   ")
			.append("   AUTH_PW    VARCHAR(256),   ")
			.append("   CONSTRAINT IDX_SSO_MSVR_PK ")
			.append("   PRIMARY KEY (CODE)         ")
			.append(" )                            ")
			.append(" WITH ( OIDS = FALSE )        ");

		pstmt = conn.prepareStatement(query29.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query31 = new StringBuffer();
			query31.append("DROP TABLE SSO_URPY ");

			pstmt = conn.prepareStatement(query31.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query32 = new StringBuffer();
		query32.append("CREATE TABLE SSO_URPY ")
			.append(" (                                  ")
			.append("   URPY_CODE          VARCHAR(20) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR(256), ")
			.append("   PW_CHANGE_WARN     VARCHAR(256), ")
			.append("   PW_VALIDATE        VARCHAR(256), ")
			.append("   SESSION_TIME       VARCHAR(256), ")
			.append("   POLLING_TIME       VARCHAR(256), ")
			.append("   CONSTRAINT IDX_SSO_URPY_PK       ")
			.append("   PRIMARY KEY (URPY_CODE)          ")
			.append(" )                                  ")
			.append(" WITH ( OIDS = FALSE )              ");

		pstmt = conn.prepareStatement(query32.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query34 = new StringBuffer();
			query34.append("DROP TABLE SSO_USER ");

			pstmt = conn.prepareStatement(query34.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query35 = new StringBuffer();
		query35.append("CREATE TABLE SSO_USER ")
			.append(" (                                  ")
			.append("   ID                 VARCHAR(100) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PASSWORD           VARCHAR(256), ")
			.append("   DN                 VARCHAR(256), ")
			.append("   STATUS             VARCHAR(1),   ")
			.append("   URPY_CODE          VARCHAR(20),  ")
			.append("   PW_MISMATCH_COUNT  VARCHAR(8),   ")
			.append("   PW_UPDATE_TIME     TIMESTAMP,    ")
			.append("   LOGIN_IP           VARCHAR(100), ")
			.append("   LOGIN_BR           VARCHAR(2),   ")
			.append("   LOGIN_TIME         TIMESTAMP,    ")
			.append("   LAST_LOGIN_IP      VARCHAR(100), ")
			.append("   LAST_LOGIN_TIME    TIMESTAMP,    ")
			.append("   CS_LOGIN_TIME      TIMESTAMP,    ")
			.append("   ACCESS_TIME        TIMESTAMP,    ")
			.append("   EMAIL              VARCHAR(100), ")
			.append("   PHONE              VARCHAR(100), ")
			.append("   ADDRESS            VARCHAR(100), ")
			.append("   CONSTRAINT IDX_SSO_USER_PK       ")
			.append("   PRIMARY KEY (ID)                 ")
			.append(" )                                  ")
			.append(" WITH ( OIDS = FALSE )              ");

		pstmt = conn.prepareStatement(query35.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query37 = new StringBuffer();
		query37.append("CREATE TABLE SSO_CLIENT ")
			.append(" ( ")
			.append("   CLIENT                      VARCHAR(100) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   ENABLED                 VARCHAR(10),  ")
			.append("   NONCE                   VARCHAR(10),  ")
			.append("   PKCE                    VARCHAR(10),  ")
			.append("   REFRESH_TOKEN_USE       VARCHAR(10),  ")
			.append("   SECRET                  VARCHAR(100), ")
			.append("   TOKEN_LIFESPAN          VARCHAR(10),  ")
			.append("   CODE_LIFESPAN           VARCHAR(10),  ")
			.append("   REFRESH_TOKEN_LIFESPAN  VARCHAR(10),  ")
			.append("   RESPONSE_TYPE           VARCHAR(10),  ")
			.append("   GRANT_TYPE              VARCHAR(30),  ")
			.append("   PROTOCOL                VARCHAR(10),  ")
			.append("   CONSTRAINT IDX_SSO_CLIENT_PK ")
			.append("   PRIMARY KEY (CLIENT) ")
			.append(" ) ")
			.append(" WITH ( OIDS = FALSE ) ");

		pstmt = conn.prepareStatement(query37.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT_SCOPE ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query39 = new StringBuffer();
		query39.append("CREATE TABLE SSO_CLIENT_SCOPE ")
			.append(" ( ")
			.append("   SCOPE   VARCHAR(100) NOT NULL, ")
			.append("   CLIENT  VARCHAR(100) NOT NULL, ")
			.append("   CONSTRAINT IDX_SSO_CLIENT_SCOPE_PK ")
			.append("   PRIMARY KEY (SCOPE, CLIENT) ")
			.append(" ) ")
			.append(" WITH ( OIDS = FALSE ) ");

		pstmt = conn.prepareStatement(query39.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query41 = new StringBuffer();
		query41.append("CREATE INDEX IDX_SSO_CLIENT_SCOPE_01 ")
		.append(" ON SSO_CLIENT_SCOPE(CLIENT) ");

		pstmt = conn.prepareStatement(query41.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT_REDIRECT ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query42 = new StringBuffer();
		query42.append("CREATE TABLE SSO_CLIENT_REDIRECT ")
			.append(" ( ")
			.append("   CLIENT     VARCHAR(100) NOT NULL, ")
			.append("   REDIRECT_URI  VARCHAR(200) NOT NULL, ")
			.append("   CONSTRAINT IDX_SSO_CLIENT_REDIRECT_PK ")
			.append("   PRIMARY KEY (CLIENT, REDIRECT_URI) ")
			.append(" ) ")
			.append(" WITH ( OIDS = FALSE ) ");

		pstmt = conn.prepareStatement(query42.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_SCOPES ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query44 = new StringBuffer();
		query44.append("CREATE TABLE SSO_SCOPES ")
			.append(" ( ")
			.append("   SCOPE  VARCHAR(100) NOT NULL, ")
			.append("   CONSTRAINT IDX_SSO_SCOPES_PK ")
			.append("   PRIMARY KEY (SCOPE) ")
			.append(" ) ")
			.append(" WITH ( OIDS = FALSE ) ");

		pstmt = conn.prepareStatement(query44.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	// MySQL
	public static void createTableIndex_mysql(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                   ")
			.append("   LOG_DATE     VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME     VARCHAR(6) NOT NULL, ")
			.append("   SEQ          VARCHAR(8) NOT NULL, ")
			.append("   USER_ID      VARCHAR(100),        ")
			.append("   USER_NAME    VARCHAR(100),        ")
			.append("   ACCESS_IP    VARCHAR(100),        ")
			.append("   ACCESS_TYPE  VARCHAR(2),          ")
			.append("   ACCESS_SP    VARCHAR(100),        ")
			.append("   ACCESS_BR    VARCHAR(2),          ")
			.append("   ACCESS_RSLT  VARCHAR(2),          ")
			.append("   CONSTRAINT IDX_SSO_ACLG_PK        ")
			.append("     PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                         ")
			.append(" COLLATE='utf8_general_ci'                 ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query04 = new StringBuffer();
			query04.append("DROP TABLE SSO_ADIP ");

			pstmt = conn.prepareStatement(query04.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query05 = new StringBuffer();
		query05.append("CREATE TABLE SSO_ADIP ")
			.append(" (                             ")
			.append("   IP  VARCHAR(256) NOT NULL,  ")
			.append("   CONSTRAINT IDX_SSO_ADIP_PK  ")
			.append("     PRIMARY KEY (IP)          ")
			.append(" )                             ")
			.append(" COLLATE='utf8_general_ci'     ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query07 = new StringBuffer();
			query07.append("DROP TABLE SSO_ADMN ");

			pstmt = conn.prepareStatement(query07.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query08 = new StringBuffer();
		query08.append("CREATE TABLE SSO_ADMN ")
			.append(" (                                  ")
			.append("   ID                 VARCHAR(100) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PASSWORD           VARCHAR(256), ")
			.append("   STATUS             VARCHAR(1),   ")
			.append("   ADPY_CODE          VARCHAR(20),  ")
			.append("   PW_MISMATCH_COUNT  VARCHAR(8),   ")
			.append("   PW_UPDATE_TIME     TIMESTAMP NULL DEFAULT NULL, ")
			.append("   ADMN_TYPE          VARCHAR(1),   ")
			.append("   EMAIL              VARCHAR(100), ")
			.append("   MENU_CODE          VARCHAR(256), ")
			.append("   LOCK_TIME          TIMESTAMP NULL DEFAULT NULL, ")
			.append("   FIRST_YN           VARCHAR(1),   ")
			.append("   USE_YN             VARCHAR(1),   ")
			.append("   LOGIN_IP           VARCHAR(100), ")
			.append("   LOGIN_BR           VARCHAR(2),   ")
			.append("   LOGIN_TIME         TIMESTAMP NULL DEFAULT NULL, ")
			.append("   ACCESS_TIME        TIMESTAMP NULL DEFAULT NULL, ")
			.append("   CONSTRAINT IDX_SSO_ADMN_PK       ")
			.append("   PRIMARY KEY (ID)                 ")
			.append(" )                                  ")
			.append(" COLLATE='utf8_general_ci'          ");

		pstmt = conn.prepareStatement(query08.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query10 = new StringBuffer();
			query10.append("DROP TABLE SSO_ADPY ");

			pstmt = conn.prepareStatement(query10.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query11 = new StringBuffer();
		query11.append("CREATE TABLE SSO_ADPY ")
			.append(" (                                  ")
			.append("   ADPY_CODE          VARCHAR(20) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR(256), ")
			.append("   SESSION_TIME       VARCHAR(256), ")
			.append("   LOCK_TIME          VARCHAR(256), ")
			.append("   IP_MAX_COUNT       VARCHAR(256), ")
			.append("   CONSTRAINT IDX_SSO_ADPY_PK       ")
			.append("   PRIMARY KEY (ADPY_CODE)          ")
			.append(" )                                  ")
			.append(" COLLATE='utf8_general_ci'          ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                                 ")
			.append("   LOG_DATE   VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME   VARCHAR(6) NOT NULL, ")
			.append("   SEQ        VARCHAR(8) NOT NULL, ")
			.append("   CASE_TYPE  VARCHAR(2),          ")
			.append("   CASE_RSLT  VARCHAR(2),          ")
			.append("   CASE_USER  VARCHAR(30),         ")
			.append("   CASE_DATA  VARCHAR(500),        ")
			.append("   CONSTRAINT IDX_SSO_AULG_PK            ")
			.append("   PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                       ")
			.append(" COLLATE='utf8_general_ci'               ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query16 = new StringBuffer();
			query16.append("DROP TABLE SSO_AUPY ");

			pstmt = conn.prepareStatement(query16.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query17 = new StringBuffer();
		query17.append("CREATE TABLE SSO_AUPY ")
			.append(" (                             ")
			.append("   CODE          VARCHAR(8) NOT NULL, ")
			.append("   WARN_LIMIT    VARCHAR(256), ")
			.append("   VERIFY_CYCLE  VARCHAR(256), ")
			.append("   VERIFY_POINT  VARCHAR(256), ")
			.append("   VERIFY_TIME   TIMESTAMP NULL DEFAULT NULL, ")
			.append("   CONSTRAINT IDX_SSO_AUPY_PK  ")
			.append("   PRIMARY KEY (CODE)          ")
			.append(" )                             ")
			.append(" COLLATE='utf8_general_ci'     ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query19 = new StringBuffer();
			query19.append("DROP TABLE SSO_CERT ");

			pstmt = conn.prepareStatement(query19.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query20 = new StringBuffer();
		query20.append("CREATE TABLE SSO_CERT ")
			.append(" (                              ")
			.append("   DN          VARCHAR(256) NOT NULL, ")
			.append("   ISSUE_DATE  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, ")
			.append("   REVOC_DATE  TIMESTAMP NULL DEFAULT NULL, ")
			.append("   STATUS      VARCHAR(1),      ")
			.append("   CERT_FILE   VARCHAR(256),    ")
			.append("   CONSTRAINT IDX_SSO_CERT_PK   ")
			.append("   PRIMARY KEY (DN, ISSUE_DATE) ")
			.append(" )                              ")
			.append(" COLLATE='utf8_general_ci'      ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query22 = new StringBuffer();
			query22.append("DROP TABLE SSO_IPLG ");

			pstmt = conn.prepareStatement(query22.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query23 = new StringBuffer();
		query23.append("CREATE TABLE SSO_IPLG ")
			.append(" (                            ")
			.append("   IP          VARCHAR(100) NOT NULL, ")
			.append("   LOGIN_ID    VARCHAR(100),  ")
			.append("   LOGIN_BR    VARCHAR(2),    ")
			.append("   LOGIN_TIME  TIMESTAMP NULL DEFAULT NULL, ")
			.append("   CONSTRAINT IDX_SSO_IPLG_PK ")
			.append("   PRIMARY KEY (IP)           ")
			.append(" )                            ")
			.append(" COLLATE='utf8_general_ci'    ");

		pstmt = conn.prepareStatement(query23.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query25 = new StringBuffer();
			query25.append("DROP TABLE SSO_MSND ");

			pstmt = conn.prepareStatement(query25.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query26 = new StringBuffer();
		query26.append("CREATE TABLE SSO_MSND ")
			.append(" (                            ")
			.append("   CODE      VARCHAR(8) NOT NULL, ")
			.append("   REFERRER  VARCHAR(512),    ")
			.append("   SUBJECT   VARCHAR(512),    ")
			.append("   BODY      VARCHAR(512),    ")
			.append("   CONSTRAINT IDX_SSO_MSND_PK ")
			.append("   PRIMARY KEY (CODE)         ")
			.append(" )                            ")
			.append(" COLLATE='utf8_general_ci'    ");

		pstmt = conn.prepareStatement(query26.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query28 = new StringBuffer();
			query28.append("DROP TABLE SSO_MSVR ");

			pstmt = conn.prepareStatement(query28.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query29 = new StringBuffer();
		query29.append("CREATE TABLE SSO_MSVR ")
			.append(" (                            ")
			.append("   CODE       VARCHAR(20) NOT NULL, ")
			.append("   SMTP_HOST  VARCHAR(256),   ")
			.append("   SMTP_PORT  VARCHAR(256),   ")
			.append("   SMTP_CHNL  VARCHAR(256),   ")
			.append("   SMTP_AUTH  VARCHAR(256),   ")
			.append("   AUTH_ID    VARCHAR(256),   ")
			.append("   AUTH_PW    VARCHAR(256),   ")
			.append("   CONSTRAINT IDX_SSO_MSVR_PK ")
			.append("   PRIMARY KEY (CODE)         ")
			.append(" )                            ")
			.append(" COLLATE='utf8_general_ci'    ");

		pstmt = conn.prepareStatement(query29.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query31 = new StringBuffer();
			query31.append("DROP TABLE SSO_URPY ");

			pstmt = conn.prepareStatement(query31.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query32 = new StringBuffer();
		query32.append("CREATE TABLE SSO_URPY ")
			.append(" (                                  ")
			.append("   URPY_CODE          VARCHAR(20) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR(256), ")
			.append("   PW_CHANGE_WARN     VARCHAR(256), ")
			.append("   PW_VALIDATE        VARCHAR(256), ")
			.append("   SESSION_TIME       VARCHAR(256), ")
			.append("   POLLING_TIME       VARCHAR(256), ")
			.append("   CONSTRAINT IDX_SSO_URPY_PK       ")
			.append("   PRIMARY KEY (URPY_CODE)          ")
			.append(" )                                  ")
			.append(" COLLATE='utf8_general_ci'          ");

		pstmt = conn.prepareStatement(query32.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query34 = new StringBuffer();
			query34.append("DROP TABLE SSO_USER ");

			pstmt = conn.prepareStatement(query34.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query35 = new StringBuffer();
		query35.append("CREATE TABLE SSO_USER ")
			.append(" (                                  ")
			.append("   ID                 VARCHAR(100) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PASSWORD           VARCHAR(256), ")
			.append("   DN                 VARCHAR(256), ")
			.append("   STATUS             VARCHAR(1),   ")
			.append("   URPY_CODE          VARCHAR(20),  ")
			.append("   PW_MISMATCH_COUNT  VARCHAR(8),   ")
			.append("   PW_UPDATE_TIME     TIMESTAMP NULL DEFAULT NULL, ")
			.append("   LOGIN_IP           VARCHAR(100), ")
			.append("   LOGIN_BR           VARCHAR(2),   ")
			.append("   LOGIN_TIME         TIMESTAMP NULL DEFAULT NULL, ")
			.append("   LAST_LOGIN_IP      VARCHAR(100), ")
			.append("   LAST_LOGIN_TIME    TIMESTAMP NULL DEFAULT NULL, ")
			.append("   CS_LOGIN_TIME      TIMESTAMP NULL DEFAULT NULL, ")
			.append("   ACCESS_TIME        TIMESTAMP NULL DEFAULT NULL, ")
			.append("   EMAIL              VARCHAR(100), ")
			.append("   PHONE              VARCHAR(100), ")
			.append("   ADDRESS            VARCHAR(100), ")
			.append("   CONSTRAINT IDX_SSO_USER_PK       ")
			.append("   PRIMARY KEY (ID)                 ")
			.append(" )                                  ")
			.append(" COLLATE='utf8_general_ci'          ");

		pstmt = conn.prepareStatement(query35.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query37 = new StringBuffer();
		query37.append("CREATE TABLE SSO_CLIENT ")
			.append(" ( ")
			.append("   CLIENT                      VARCHAR(100) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   ENABLED                 VARCHAR(10),  ")
			.append("   NONCE                   VARCHAR(10),  ")
			.append("   PKCE                    VARCHAR(10),  ")
			.append("   REFRESH_TOKEN_USE       VARCHAR(10),  ")
			.append("   SECRET                  VARCHAR(100), ")
			.append("   TOKEN_LIFESPAN          VARCHAR(10),  ")
			.append("   CODE_LIFESPAN           VARCHAR(10),  ")
			.append("   REFRESH_TOKEN_LIFESPAN  VARCHAR(10),  ")
			.append("   RESPONSE_TYPE           VARCHAR(10),  ")
			.append("   GRANT_TYPE              VARCHAR(30),  ")
			.append("   PROTOCOL                VARCHAR(10),  ")
			.append("   CONSTRAINT IDX_SSO_CLIENT_PK ")
			.append("   PRIMARY KEY (CLIENT) ")
			.append(" ) ")
			.append(" COLLATE='utf8_general_ci' ");

		pstmt = conn.prepareStatement(query37.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT_SCOPE ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query39 = new StringBuffer();
		query39.append("CREATE TABLE SSO_CLIENT_SCOPE ")
			.append(" ( ")
			.append("   SCOPE   VARCHAR(100) NOT NULL, ")
			.append("   CLIENT  VARCHAR(100) NOT NULL, ")
			.append("   CONSTRAINT IDX_SSO_CLIENT_SCOPE_PK ")
			.append("   PRIMARY KEY (SCOPE, CLIENT) ")
			.append(" ) ")
			.append(" COLLATE='utf8_general_ci' ");

		pstmt = conn.prepareStatement(query39.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query41 = new StringBuffer();
		query41.append("CREATE INDEX IDX_SSO_CLIENT_SCOPE_01 ")
		.append(" ON SSO_CLIENT_SCOPE(CLIENT) ");

		pstmt = conn.prepareStatement(query41.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT_REDIRECT ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query42 = new StringBuffer();
		query42.append("CREATE TABLE SSO_CLIENT_REDIRECT ")
			.append(" ( ")
			.append("   CLIENT     VARCHAR(100) NOT NULL, ")
			.append("   REDIRECT_URI  VARCHAR(200) NOT NULL, ")
			.append("   CONSTRAINT IDX_SSO_CLIENT_REDIRECT_PK ")
			.append("   PRIMARY KEY (CLIENT, REDIRECT_URI) ")
			.append(" ) ")
			.append(" COLLATE='utf8_general_ci' ");

		pstmt = conn.prepareStatement(query42.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_SCOPES ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query44 = new StringBuffer();
		query44.append("CREATE TABLE SSO_SCOPES ")
			.append(" ( ")
			.append("   SCOPE  VARCHAR(100) NOT NULL, ")
			.append("   CONSTRAINT IDX_SSO_SCOPES_PK ")
			.append("   PRIMARY KEY (SCOPE) ")
			.append(" ) ")
			.append(" COLLATE='utf8_general_ci' ");

		pstmt = conn.prepareStatement(query44.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	// SQL Server
	public static void createTableIndex_sqlserver(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                   ")
			.append("   LOG_DATE     VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME     VARCHAR(6) NOT NULL, ")
			.append("   SEQ          VARCHAR(8) NOT NULL, ")
			.append("   USER_ID      VARCHAR(100),        ")
			.append("   USER_NAME    VARCHAR(100),        ")
			.append("   ACCESS_IP    VARCHAR(100),        ")
			.append("   ACCESS_TYPE  VARCHAR(2),          ")
			.append("   ACCESS_SP    VARCHAR(100),        ")
			.append("   ACCESS_BR    VARCHAR(2),          ")
			.append("   ACCESS_RSLT  VARCHAR(2),          ")
			.append("   CONSTRAINT IDX_SSO_ACLG_PK        ")
			.append("     PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                         ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query04 = new StringBuffer();
			query04.append("DROP TABLE SSO_ADIP ");

			pstmt = conn.prepareStatement(query04.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query05 = new StringBuffer();
		query05.append("CREATE TABLE SSO_ADIP ")
			.append(" (                             ")
			.append("   IP  VARCHAR(256) NOT NULL,  ")
			.append("   CONSTRAINT IDX_SSO_ADIP_PK  ")
			.append("     PRIMARY KEY (IP)          ")
			.append(" )                             ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query07 = new StringBuffer();
			query07.append("DROP TABLE SSO_ADMN ");

			pstmt = conn.prepareStatement(query07.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query08 = new StringBuffer();
		query08.append("CREATE TABLE SSO_ADMN ")
			.append(" (                                  ")
			.append("   ID                 VARCHAR(100) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PASSWORD           VARCHAR(256), ")
			.append("   STATUS             VARCHAR(1),   ")
			.append("   ADPY_CODE          VARCHAR(20),  ")
			.append("   PW_MISMATCH_COUNT  VARCHAR(8),   ")
			.append("   PW_UPDATE_TIME     DATETIME,     ")
			.append("   ADMN_TYPE          VARCHAR(1),   ")
			.append("   EMAIL              VARCHAR(100), ")
			.append("   MENU_CODE          VARCHAR(256), ")
			.append("   LOCK_TIME          DATETIME,     ")
			.append("   FIRST_YN           VARCHAR(1),   ")
			.append("   USE_YN             VARCHAR(1),   ")
			.append("   LOGIN_IP           VARCHAR(100), ")
			.append("   LOGIN_BR           VARCHAR(2),   ")
			.append("   LOGIN_TIME         DATETIME,     ")
			.append("   ACCESS_TIME        DATETIME,     ")
			.append("   CONSTRAINT IDX_SSO_ADMN_PK       ")
			.append("   PRIMARY KEY (ID)                 ")
			.append(" )                                  ");

		pstmt = conn.prepareStatement(query08.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query10 = new StringBuffer();
			query10.append("DROP TABLE SSO_ADPY ");

			pstmt = conn.prepareStatement(query10.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query11 = new StringBuffer();
		query11.append("CREATE TABLE SSO_ADPY ")
			.append(" (                                  ")
			.append("   ADPY_CODE          VARCHAR(20) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR(256), ")
			.append("   SESSION_TIME       VARCHAR(256), ")
			.append("   LOCK_TIME          VARCHAR(256), ")
			.append("   IP_MAX_COUNT       VARCHAR(256), ")
			.append("   CONSTRAINT IDX_SSO_ADPY_PK       ")
			.append("   PRIMARY KEY (ADPY_CODE)          ")
			.append(" )                                  ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                                 ")
			.append("   LOG_DATE   VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME   VARCHAR(6) NOT NULL, ")
			.append("   SEQ        VARCHAR(8) NOT NULL, ")
			.append("   CASE_TYPE  VARCHAR(2),          ")
			.append("   CASE_RSLT  VARCHAR(2),          ")
			.append("   CASE_USER  VARCHAR(30),         ")
			.append("   CASE_DATA  VARCHAR(500),        ")
			.append("   CONSTRAINT IDX_SSO_AULG_PK            ")
			.append("   PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                       ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query16 = new StringBuffer();
			query16.append("DROP TABLE SSO_AUPY ");

			pstmt = conn.prepareStatement(query16.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query17 = new StringBuffer();
		query17.append("CREATE TABLE SSO_AUPY ")
			.append(" (                             ")
			.append("   CODE          VARCHAR(8) NOT NULL, ")
			.append("   WARN_LIMIT    VARCHAR(256), ")
			.append("   VERIFY_CYCLE  VARCHAR(256), ")
			.append("   VERIFY_POINT  VARCHAR(256), ")
			.append("   VERIFY_TIME   DATETIME,     ")
			.append("   CONSTRAINT IDX_SSO_AUPY_PK  ")
			.append("   PRIMARY KEY (CODE)          ")
			.append(" )                             ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query19 = new StringBuffer();
			query19.append("DROP TABLE SSO_CERT ");

			pstmt = conn.prepareStatement(query19.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query20 = new StringBuffer();
		query20.append("CREATE TABLE SSO_CERT ")
			.append(" (                              ")
			.append("   DN          VARCHAR(256) NOT NULL, ")
			.append("   ISSUE_DATE  DATETIME NOT NULL DEFAULT GETDATE(), ")
			.append("   REVOC_DATE  DATETIME,        ")
			.append("   STATUS      VARCHAR(1),      ")
			.append("   CERT_FILE   VARCHAR(256),    ")
			.append("   CONSTRAINT IDX_SSO_CERT_PK   ")
			.append("   PRIMARY KEY (DN, ISSUE_DATE) ")
			.append(" )                              ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query22 = new StringBuffer();
			query22.append("DROP TABLE SSO_IPLG ");

			pstmt = conn.prepareStatement(query22.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query23 = new StringBuffer();
		query23.append("CREATE TABLE SSO_IPLG ")
			.append(" (                            ")
			.append("   IP          VARCHAR(100) NOT NULL, ")
			.append("   LOGIN_ID    VARCHAR(100),  ")
			.append("   LOGIN_BR    VARCHAR(2),    ")
			.append("   LOGIN_TIME  DATETIME,      ")
			.append("   CONSTRAINT IDX_SSO_IPLG_PK ")
			.append("   PRIMARY KEY (IP)           ")
			.append(" )                            ");

		pstmt = conn.prepareStatement(query23.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query25 = new StringBuffer();
			query25.append("DROP TABLE SSO_MSND ");

			pstmt = conn.prepareStatement(query25.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query26 = new StringBuffer();
		query26.append("CREATE TABLE SSO_MSND ")
			.append(" (                            ")
			.append("   CODE      VARCHAR(8) NOT NULL, ")
			.append("   REFERRER  VARCHAR(512),    ")
			.append("   SUBJECT   VARCHAR(512),    ")
			.append("   BODY      VARCHAR(512),    ")
			.append("   CONSTRAINT IDX_SSO_MSND_PK ")
			.append("   PRIMARY KEY (CODE)         ")
			.append(" )                            ");

		pstmt = conn.prepareStatement(query26.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query28 = new StringBuffer();
			query28.append("DROP TABLE SSO_MSVR ");

			pstmt = conn.prepareStatement(query28.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query29 = new StringBuffer();
		query29.append("CREATE TABLE SSO_MSVR ")
			.append(" (                            ")
			.append("   CODE       VARCHAR(20) NOT NULL, ")
			.append("   SMTP_HOST  VARCHAR(256),   ")
			.append("   SMTP_PORT  VARCHAR(256),   ")
			.append("   SMTP_CHNL  VARCHAR(256),   ")
			.append("   SMTP_AUTH  VARCHAR(256),   ")
			.append("   AUTH_ID    VARCHAR(256),   ")
			.append("   AUTH_PW    VARCHAR(256),   ")
			.append("   CONSTRAINT IDX_SSO_MSVR_PK ")
			.append("   PRIMARY KEY (CODE)         ")
			.append(" )                            ");

		pstmt = conn.prepareStatement(query29.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query31 = new StringBuffer();
			query31.append("DROP TABLE SSO_URPY ");

			pstmt = conn.prepareStatement(query31.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query32 = new StringBuffer();
		query32.append("CREATE TABLE SSO_URPY ")
			.append(" (                                  ")
			.append("   URPY_CODE          VARCHAR(20) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR(256), ")
			.append("   PW_CHANGE_WARN     VARCHAR(256), ")
			.append("   PW_VALIDATE        VARCHAR(256), ")
			.append("   SESSION_TIME       VARCHAR(256), ")
			.append("   POLLING_TIME       VARCHAR(256), ")
			.append("   CONSTRAINT IDX_SSO_URPY_PK       ")
			.append("   PRIMARY KEY (URPY_CODE)          ")
			.append(" )                                  ");

		pstmt = conn.prepareStatement(query32.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query34 = new StringBuffer();
			query34.append("DROP TABLE SSO_USER ");

			pstmt = conn.prepareStatement(query34.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query35 = new StringBuffer();
		query35.append("CREATE TABLE SSO_USER ")
			.append(" (                                  ")
			.append("   ID                 VARCHAR(100) NOT NULL, ")
			.append("   NAME               VARCHAR(100), ")
			.append("   PASSWORD           VARCHAR(256), ")
			.append("   DN                 VARCHAR(256), ")
			.append("   STATUS             VARCHAR(1),   ")
			.append("   URPY_CODE          VARCHAR(20),  ")
			.append("   PW_MISMATCH_COUNT  VARCHAR(8),   ")
			.append("   PW_UPDATE_TIME     DATETIME,     ")
			.append("   LOGIN_IP           VARCHAR(100), ")
			.append("   LOGIN_BR           VARCHAR(2),   ")
			.append("   LOGIN_TIME         DATETIME,     ")
			.append("   LAST_LOGIN_IP      VARCHAR(100), ")
			.append("   LAST_LOGIN_TIME    DATETIME,     ")
			.append("   CS_LOGIN_TIME      DATETIME,     ")
			.append("   ACCESS_TIME        DATETIME,     ")
			.append("   EMAIL              VARCHAR(100), ")
			.append("   PHONE              VARCHAR(100), ")
			.append("   ADDRESS            VARCHAR(100), ")
			.append("   CONSTRAINT IDX_SSO_USER_PK       ")
			.append("   PRIMARY KEY (ID)                 ")
			.append(" )                                  ");

		pstmt = conn.prepareStatement(query35.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query37 = new StringBuffer();
		query37.append("CREATE TABLE SSO_CLIENT ")
			.append(" ( ")
			.append("   CLIENT                  VARCHAR(100) NOT NULL, ")
			.append("   NAME                    VARCHAR(100), ")
			.append("   ENABLED                 VARCHAR(10),  ")
			.append("   NONCE                   VARCHAR(10),  ")
			.append("   PKCE                    VARCHAR(10),  ")
			.append("   REFRESH_TOKEN_USE       VARCHAR(10),  ")
			.append("   SECRET                  VARCHAR(100), ")
			.append("   TOKEN_LIFESPAN          VARCHAR(10),  ")
			.append("   CODE_LIFESPAN           VARCHAR(10),  ")
			.append("   REFRESH_TOKEN_LIFESPAN  VARCHAR(10),  ")
			.append("   RESPONSE_TYPE           VARCHAR(10),  ")
			.append("   GRANT_TYPE              VARCHAR(30),  ")
			.append("   PROTOCOL                VARCHAR(10),  ")
			.append("   CONSTRAINT IDX_SSO_CLIENT_PK ")
			.append("   PRIMARY KEY (CLIENT) ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query37.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT_SCOPE ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query39 = new StringBuffer();
		query39.append("CREATE TABLE SSO_CLIENT_SCOPE ")
			.append(" ( ")
			.append("   SCOPE   VARCHAR(100) NOT NULL, ")
			.append("   CLIENT  VARCHAR(100) NOT NULL, ")
			.append("   CONSTRAINT IDX_SSO_CLIENT_SCOPE_PK ")
			.append("   PRIMARY KEY (SCOPE, CLIENT) ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query39.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query41 = new StringBuffer();
		query41.append("CREATE INDEX IDX_SSO_CLIENT_SCOPE_01 ")
		.append(" ON SSO_CLIENT_SCOPE(CLIENT) ");

		pstmt = conn.prepareStatement(query41.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_CLIENT_REDIRECT ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query42 = new StringBuffer();
		query42.append("CREATE TABLE SSO_CLIENT_REDIRECT ")
			.append(" ( ")
			.append("   CLIENT     VARCHAR(100) NOT NULL, ")
			.append("   REDIRECT_URI  VARCHAR(200) NOT NULL, ")
			.append("   CONSTRAINT IDX_SSO_CLIENT_REDIRECT_PK ")
			.append("   PRIMARY KEY (CLIENT, REDIRECT_URI) ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query42.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query = new StringBuffer();
			query.append("DROP TABLE SSO_SCOPES ");

			pstmt = conn.prepareStatement(query.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query44 = new StringBuffer();
		query44.append("CREATE TABLE SSO_SCOPES ")
			.append(" ( ")
			.append("   SCOPE  VARCHAR(100) NOT NULL, ")
			.append("   CONSTRAINT IDX_SSO_SCOPES_PK ")
			.append("   PRIMARY KEY (SCOPE) ")
			.append(" ) ");

		pstmt = conn.prepareStatement(query44.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	public static void createTableIndex_tibero(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		String tablespace = "";
		if (!dbtsp.isEmpty()) {
			tablespace = " TABLESPACE " + dbtsp;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                      ")
			.append("   LOG_DATE     VARCHAR2(8 BYTE),       ")
			.append("   LOG_TIME     VARCHAR2(6 BYTE),       ")
			.append("   SEQ          VARCHAR2(8 BYTE),       ")
			.append("   USER_ID      VARCHAR2(100 BYTE),     ")
			.append("   USER_NAME    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_IP    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_TYPE  VARCHAR2(2 BYTE),       ")
			.append("   ACCESS_SP    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_BR    VARCHAR2(2 BYTE),       ")
			.append("   ACCESS_RSLT  VARCHAR2(2 BYTE)        ")
			.append(" )                                      ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		StringBuffer query03 = new StringBuffer();
		query03.append("ALTER TABLE SSO_ACLG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ACLG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query04 = new StringBuffer();
			query04.append("DROP TABLE SSO_ADIP ");

			pstmt = conn.prepareStatement(query04.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query05 = new StringBuffer();
		query05.append("CREATE TABLE SSO_ADIP ")
			.append(" (                                      ")
			.append("   IP  VARCHAR2(256 BYTE)               ")
			.append(" )                                      ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query05.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query06 = new StringBuffer();
		query06.append("ALTER TABLE SSO_ADIP ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ADIP_PK             ")
			.append(" PRIMARY KEY (IP)                       ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query06.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query07 = new StringBuffer();
			query07.append("DROP TABLE SSO_ADMN ");

			pstmt = conn.prepareStatement(query07.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query08 = new StringBuffer();
		query08.append("CREATE TABLE SSO_ADMN ")
			.append(" (                                        ")
			.append("   ID                 VARCHAR2(100 BYTE), ")
			.append("   NAME               VARCHAR2(100 BYTE), ")
			.append("   PASSWORD           VARCHAR2(256 BYTE), ")
			.append("   STATUS             VARCHAR2(1 BYTE),   ")
			.append("   ADPY_CODE          VARCHAR2(20 BYTE),  ")
			.append("   PW_MISMATCH_COUNT  VARCHAR2(8 BYTE),   ")
			.append("   PW_UPDATE_TIME     DATE,               ")
			.append("   ADMN_TYPE          VARCHAR2(1 BYTE),   ")
			.append("   EMAIL              VARCHAR2(100 BYTE), ")
			.append("   MENU_CODE          VARCHAR2(256 BYTE), ")
			.append("   LOCK_TIME          DATE,               ")
			.append("   FIRST_YN           VARCHAR2(1 BYTE),   ")
			.append("   USE_YN             VARCHAR2(1 BYTE),   ")
			.append("   LOGIN_IP           VARCHAR2(100 BYTE), ")
			.append("   LOGIN_BR           VARCHAR2(2 BYTE),   ")
			.append("   LOGIN_TIME         DATE,               ")
			.append("   ACCESS_TIME        DATE                ")
			.append(" )                                        ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query08.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query09 = new StringBuffer();
		query09.append("ALTER TABLE SSO_ADMN ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ADMN_PK             ")
			.append(" PRIMARY KEY (ID)                       ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query09.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query10 = new StringBuffer();
			query10.append("DROP TABLE SSO_ADPY ");

			pstmt = conn.prepareStatement(query10.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query11 = new StringBuffer();
		query11.append("CREATE TABLE SSO_ADPY ")
			.append(" (                                        ")
			.append("   ADPY_CODE          VARCHAR2(20 BYTE),  ")
			.append("   NAME               VARCHAR2(100 BYTE), ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR2(256 BYTE), ")
			.append("   SESSION_TIME       VARCHAR2(256 BYTE), ")
			.append("   LOCK_TIME          VARCHAR2(256 BYTE), ")
			.append("   IP_MAX_COUNT       VARCHAR2(256 BYTE)  ")
			.append(" )                                        ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query11.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query12 = new StringBuffer();
		query12.append("ALTER TABLE SSO_ADPY ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ADPY_PK             ")
			.append(" PRIMARY KEY (ADPY_CODE)                ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query12.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                               ")
			.append("   LOG_DATE   VARCHAR2(8 BYTE),  ")
			.append("   LOG_TIME   VARCHAR2(6 BYTE),  ")
			.append("   SEQ        VARCHAR2(8 BYTE),  ")
			.append("   CASE_TYPE  VARCHAR2(2 BYTE),  ")
			.append("   CASE_RSLT  VARCHAR2(2 BYTE),  ")
			.append("   CASE_USER  VARCHAR2(30 BYTE), ")
			.append("   CASE_DATA  VARCHAR2(500 BYTE) ")
			.append(" )                               ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query15 = new StringBuffer();
		query15.append("ALTER TABLE SSO_AULG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_AULG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query16 = new StringBuffer();
			query16.append("DROP TABLE SSO_AUPY ");

			pstmt = conn.prepareStatement(query16.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query17 = new StringBuffer();
		query17.append("CREATE TABLE SSO_AUPY ")
			.append(" (                                   ")
			.append("   CODE          VARCHAR2(8 BYTE),   ")
			.append("   WARN_LIMIT    VARCHAR2(256 BYTE), ")
			.append("   VERIFY_CYCLE  VARCHAR2(256 BYTE), ")
			.append("   VERIFY_POINT  VARCHAR2(256 BYTE), ")
			.append("   VERIFY_TIME   DATE                ")
			.append(" )                                   ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query17.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query18 = new StringBuffer();
		query18.append("ALTER TABLE SSO_AUPY ADD ( ")
			.append(" CONSTRAINT IDX_SSO_AUPY_PK             ")
			.append(" PRIMARY KEY (CODE)                     ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query18.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query19 = new StringBuffer();
			query19.append("DROP TABLE SSO_CERT ");

			pstmt = conn.prepareStatement(query19.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query20 = new StringBuffer();
		query20.append("CREATE TABLE SSO_CERT ")
			.append(" (                                 ")
			.append("   DN          VARCHAR2(256 BYTE), ")
			.append("   ISSUE_DATE  DATE,               ")
			.append("   REVOC_DATE  DATE,               ")
			.append("   STATUS      VARCHAR2(1 BYTE),   ")
			.append("   CERT_FILE   VARCHAR2(256 BYTE)  ")
			.append(" )                                 ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query20.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query21 = new StringBuffer();
		query21.append("ALTER TABLE SSO_CERT ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CERT_PK             ")
			.append(" PRIMARY KEY (DN, ISSUE_DATE)           ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query21.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query22 = new StringBuffer();
			query22.append("DROP TABLE SSO_IPLG ");

			pstmt = conn.prepareStatement(query22.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query23 = new StringBuffer();
		query23.append("CREATE TABLE SSO_IPLG ")
			.append(" (                                 ")
			.append("   IP          VARCHAR2(100 BYTE), ")
			.append("   LOGIN_ID    VARCHAR2(100 BYTE), ")
			.append("   LOGIN_BR    VARCHAR2(2 BYTE),   ")
			.append("   LOGIN_TIME  DATE                ")
			.append(" )                                 ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query23.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query24 = new StringBuffer();
		query24.append("ALTER TABLE SSO_IPLG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_IPLG_PK             ")
			.append(" PRIMARY KEY (IP)                       ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query24.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query25 = new StringBuffer();
			query25.append("DROP TABLE SSO_MSND ");

			pstmt = conn.prepareStatement(query25.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query26 = new StringBuffer();
		query26.append("CREATE TABLE SSO_MSND ")
			.append(" (                               ")
			.append("   CODE      VARCHAR2(8 BYTE),   ")
			.append("   REFERRER  VARCHAR2(512 BYTE), ")
			.append("   SUBJECT   VARCHAR2(512 BYTE), ")
			.append("   BODY      VARCHAR2(512 BYTE)  ")
			.append(" )                               ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query26.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query27 = new StringBuffer();
		query27.append("ALTER TABLE SSO_MSND ADD ( ")
			.append(" CONSTRAINT IDX_SSO_MSND_PK             ")
			.append(" PRIMARY KEY (CODE)                     ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query27.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query28 = new StringBuffer();
			query28.append("DROP TABLE SSO_MSVR ");

			pstmt = conn.prepareStatement(query28.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query29 = new StringBuffer();
		query29.append("CREATE TABLE SSO_MSVR ")
			.append(" (                                ")
			.append("   CODE       VARCHAR2(20 BYTE),  ")
			.append("   SMTP_HOST  VARCHAR2(256 BYTE), ")
			.append("   SMTP_PORT  VARCHAR2(256 BYTE), ")
			.append("   SMTP_CHNL  VARCHAR2(256 BYTE), ")
			.append("   SMTP_AUTH  VARCHAR2(256 BYTE), ")
			.append("   AUTH_ID    VARCHAR2(256 BYTE), ")
			.append("   AUTH_PW    VARCHAR2(256 BYTE)  ")
			.append(" )                                ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query29.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query30 = new StringBuffer();
		query30.append("ALTER TABLE SSO_MSVR ADD ( ")
			.append(" CONSTRAINT IDX_SSO_MSVR_PK             ")
			.append(" PRIMARY KEY (CODE)                     ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query30.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query31 = new StringBuffer();
			query31.append("DROP TABLE SSO_URPY ");

			pstmt = conn.prepareStatement(query31.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query32 = new StringBuffer();
		query32.append("CREATE TABLE SSO_URPY ")
			.append(" (                                        ")
			.append("   URPY_CODE          VARCHAR2(20 BYTE),  ")
			.append("   NAME               VARCHAR2(100 BYTE), ")
			.append("   PW_MISMATCH_ALLOW  VARCHAR2(256 BYTE), ")
			.append("   PW_CHANGE_WARN     VARCHAR2(256 BYTE), ")
			.append("   PW_VALIDATE        VARCHAR2(256 BYTE), ")
			.append("   SESSION_TIME       VARCHAR2(256 BYTE), ")
			.append("   POLLING_TIME       VARCHAR2(256 BYTE)  ")
			.append(" )                                        ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query32.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query33 = new StringBuffer();
		query33.append("ALTER TABLE SSO_URPY ADD ( ")
			.append(" CONSTRAINT IDX_SSO_URPY_PK             ")
			.append(" PRIMARY KEY (URPY_CODE)                ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query33.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query34 = new StringBuffer();
			query34.append("DROP TABLE SSO_USER ");

			pstmt = conn.prepareStatement(query34.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query35 = new StringBuffer();
		query35.append("CREATE TABLE SSO_USER ")
			.append(" (                                        ")
			.append("   ID                 VARCHAR2(100 BYTE), ")
			.append("   NAME               VARCHAR2(100 BYTE), ")
			.append("   PASSWORD           VARCHAR2(256 BYTE), ")
			.append("   DN                 VARCHAR2(256 BYTE), ")
			.append("   STATUS             VARCHAR2(1 BYTE),   ")
			.append("   URPY_CODE          VARCHAR2(20 BYTE),  ")
			.append("   PW_MISMATCH_COUNT  VARCHAR2(8 BYTE),   ")
			.append("   PW_UPDATE_TIME     DATE,               ")
			.append("   LOGIN_IP           VARCHAR2(100 BYTE), ")
			.append("   LOGIN_BR           VARCHAR2(2 BYTE),   ")
			.append("   LOGIN_TIME         DATE,               ")
			.append("   LAST_LOGIN_IP      VARCHAR2(100 BYTE), ")
			.append("   LAST_LOGIN_TIME    DATE,               ")
			.append("   CS_LOGIN_TIME      DATE,               ")
			.append("   ACCESS_TIME        DATE,               ")
			.append("   EMAIL              VARCHAR2(100 BYTE), ")
			.append("   PHONE              VARCHAR2(100 BYTE), ")
			.append("   ADDRESS            VARCHAR2(100 BYTE)  ")
			.append(" )                                        ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query35.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query36 = new StringBuffer();
		query36.append("ALTER TABLE SSO_USER ADD ( ")
			.append(" CONSTRAINT IDX_SSO_USER_PK             ")
			.append(" PRIMARY KEY (ID)                       ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query36.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query00 = new StringBuffer();
			query00.append("DROP TABLE SSO_CLIENT ");

			pstmt = conn.prepareStatement(query00.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query37 = new StringBuffer();
		query37.append("CREATE TABLE SSO_CLIENT ")
			.append(" ( ")
			.append("   CLIENT                      VARCHAR2(100 BYTE), ")
			.append("   NAME               VARCHAR2(100 BYTE), ")
			.append("   ENABLED                 VARCHAR2(10 BYTE),  ")
			.append("   NONCE                   VARCHAR2(10 BYTE),  ")
			.append("   PKCE                    VARCHAR2(10 BYTE),  ")
			.append("   REFRESH_TOKEN_USE       VARCHAR2(10 BYTE),  ")
			.append("   SECRET                  VARCHAR2(100 BYTE), ")
			.append("   TOKEN_LIFESPAN          VARCHAR2(10 BYTE),  ")
			.append("   CODE_LIFESPAN           VARCHAR2(10 BYTE),  ")
			.append("   REFRESH_TOKEN_LIFESPAN  VARCHAR2(10 BYTE),  ")
			.append("   RESPONSE_TYPE           VARCHAR2(10 BYTE),  ")
			.append("   GRANT_TYPE              VARCHAR2(30 BYTE),  ")
			.append("   PROTOCOL                VARCHAR2(10 BYTE)   ")
			.append(" ) ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query37.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query38 = new StringBuffer();
		query38.append("ALTER TABLE SSO_CLIENT ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CLIENT_PK      ")
			.append(" PRIMARY KEY (CLIENT)                       ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query38.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query00 = new StringBuffer();
			query00.append("DROP TABLE SSO_CLIENT_SCOPE ");

			pstmt = conn.prepareStatement(query00.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query39 = new StringBuffer();
		query39.append("CREATE TABLE SSO_CLIENT_SCOPE ")
			.append(" ( ")
			.append("   SCOPE   VARCHAR2(100 BYTE), ")
			.append("   CLIENT  VARCHAR2(100 BYTE)  ")
			.append(" ) ")
			.append(tablespace)
			.append(" PCTUSED    0   ")
			.append(" PCTFREE    10  ")
			.append(" INITRANS   1   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING    ")
			.append(" NOCOMPRESS ")
			.append(" NOCACHE    ")
			.append(" NOPARALLEL ")
			.append(" MONITORING ");

		pstmt = conn.prepareStatement(query39.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query40 = new StringBuffer();
		query40.append("ALTER TABLE SSO_CLIENT_SCOPE ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CLIENT_SCOPE_PK ")
			.append(" PRIMARY KEY (SCOPE, CLIENT)  ")
			.append(" USING INDEX ")
			.append(tablespace)
			.append(" PCTFREE    10  ")
			.append(" INITRANS   2   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query40.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query41 = new StringBuffer();
		query41.append("CREATE INDEX IDX_SSO_CLIENT_SCOPE_01 ")
			.append(" ON SSO_CLIENT_SCOPE(CLIENT) ")
			.append(" LOGGING ")
			.append(tablespace)
			.append(" PCTFREE    10  ")
			.append(" INITRANS   2   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ) ")
			.append(" NOPARALLEL ");

		pstmt = conn.prepareStatement(query41.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query00 = new StringBuffer();
			query00.append("DROP TABLE SSO_CLIENT_REDIRECT ");

			pstmt = conn.prepareStatement(query00.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query42 = new StringBuffer();
		query42.append("CREATE TABLE SSO_CLIENT_REDIRECT ")
			.append(" ( ")
			.append("   CLIENT     VARCHAR2(100 BYTE), ")
			.append("   REDIRECT_URI  VARCHAR2(200 BYTE)  ")
			.append(" ) ")
			.append(tablespace)
			.append(" PCTUSED    0   ")
			.append(" PCTFREE    10  ")
			.append(" INITRANS   1   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING    ")
			.append(" NOCOMPRESS ")
			.append(" NOCACHE    ")
			.append(" NOPARALLEL ")
			.append(" MONITORING ");

		pstmt = conn.prepareStatement(query42.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query43 = new StringBuffer();
		query43.append("ALTER TABLE SSO_CLIENT_REDIRECT ADD ( ")
			.append(" CONSTRAINT IDX_SSO_CLIENT_REDIRECT_PK ")
			.append(" PRIMARY KEY (CLIENT, REDIRECT_URI)  ")
			.append(" USING INDEX ")
			.append(tablespace)
			.append(" PCTFREE    10  ")
			.append(" INITRANS   2   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query43.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query00 = new StringBuffer();
			query00.append("DROP TABLE SSO_SCOPES ");

			pstmt = conn.prepareStatement(query00.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query44 = new StringBuffer();
		query44.append("CREATE TABLE SSO_SCOPES ")
			.append(" ( ")
			.append("   SCOPE  VARCHAR2(100 BYTE)  ")
			.append(" ) ")
			.append(tablespace)
			.append(" PCTUSED    0   ")
			.append(" PCTFREE    10  ")
			.append(" INITRANS   1   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING    ")
			.append(" NOCOMPRESS ")
			.append(" NOCACHE    ")
			.append(" NOPARALLEL ")
			.append(" MONITORING ");

		pstmt = conn.prepareStatement(query44.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query45 = new StringBuffer();
		query45.append("ALTER TABLE SSO_SCOPES ADD ( ")
			.append(" CONSTRAINT IDX_SSO_SCOPES_PK ")
			.append(" PRIMARY KEY (SCOPE) ")
			.append(" USING INDEX ")
			.append(tablespace)
			.append(" PCTFREE    10  ")
			.append(" INITRANS   2   ")
			.append(" MAXTRANS   255 ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query45.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	public static void createLdapTableIndex(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		String tablespace = "";
		if (!dbtsp.isEmpty()) {
			tablespace = " TABLESPACE " + dbtsp;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                      ")
			.append("   LOG_DATE     VARCHAR2(8 BYTE),       ")
			.append("   LOG_TIME     VARCHAR2(6 BYTE),       ")
			.append("   SEQ          VARCHAR2(8 BYTE),       ")
			.append("   USER_ID      VARCHAR2(100 BYTE),     ")
			.append("   USER_NAME    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_IP    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_TYPE  VARCHAR2(2 BYTE),       ")
			.append("   ACCESS_SP    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_BR    VARCHAR2(2 BYTE),       ")
			.append("   ACCESS_RSLT  VARCHAR2(2 BYTE)        ")
			.append(" )                                      ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		StringBuffer query03 = new StringBuffer();
		query03.append("ALTER TABLE SSO_ACLG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ACLG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 942) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                               ")
			.append("   LOG_DATE   VARCHAR2(8 BYTE),  ")
			.append("   LOG_TIME   VARCHAR2(6 BYTE),  ")
			.append("   SEQ        VARCHAR2(8 BYTE),  ")
			.append("   CASE_TYPE  VARCHAR2(2 BYTE),  ")
			.append("   CASE_RSLT  VARCHAR2(2 BYTE),  ")
			.append("   CASE_USER  VARCHAR2(30 BYTE), ")
			.append("   CASE_DATA  VARCHAR2(500 BYTE) ")
			.append(" )                               ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query15 = new StringBuffer();
		query15.append("ALTER TABLE SSO_AULG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_AULG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	// Cubrid
	public static void createLdapTableIndex_cubrid(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                      ")
			.append("   LOG_DATE     VARCHAR(8),       		 ")
			.append("   LOG_TIME     VARCHAR(6),       	 	 ")
			.append("   SEQ          VARCHAR(8),       		 ")
			.append("   USER_ID      VARCHAR(100),     		 ")
			.append("   USER_NAME    VARCHAR(100),     		 ")
			.append("   ACCESS_IP    VARCHAR(100),     		 ")
			.append("   ACCESS_TYPE  VARCHAR(2),       		 ")
			.append("   ACCESS_SP    VARCHAR(100),     		 ")
			.append("   ACCESS_BR    VARCHAR(2),       		 ")
			.append("   ACCESS_RSLT  VARCHAR(2)        		 ")
			.append(" )                                      ");
			
		
		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();		
		pstmt.close();
		pstmt = null;
		
		StringBuffer query03 = new StringBuffer();
		query03.append("ALTER TABLE SSO_ACLG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ACLG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -494) {
				throw new Exception(e.getMessage());
			}
			
			if (pstmt != null) {
				pstmt.close();
				pstmt = null;
			}
		}

		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                               ")
			.append("   LOG_DATE   VARCHAR(8),  	  ")
			.append("   LOG_TIME   VARCHAR(6),  	  ")
			.append("   SEQ        VARCHAR(8),  	  ")
			.append("   CASE_TYPE  VARCHAR(2),  	  ")
			.append("   CASE_RSLT  VARCHAR(2),  	  ")
			.append("   CASE_USER  VARCHAR(30), 	  ")
			.append("   CASE_DATA  VARCHAR(500) 	  ")
			.append(" )                               ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query15 = new StringBuffer();
		query15.append("ALTER TABLE SSO_AULG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_AULG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" )                          			 ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	// PostgreSQL
	public static void createLdapTableIndex_postgresql(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                   ")
			.append("   LOG_DATE     VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME     VARCHAR(6) NOT NULL, ")
			.append("   SEQ          VARCHAR(8) NOT NULL, ")
			.append("   USER_ID      VARCHAR(100),        ")
			.append("   USER_NAME    VARCHAR(100),        ")
			.append("   ACCESS_IP    VARCHAR(100),        ")
			.append("   ACCESS_TYPE  VARCHAR(2),          ")
			.append("   ACCESS_SP    VARCHAR(100),        ")
			.append("   ACCESS_BR    VARCHAR(2),          ")
			.append("   ACCESS_RSLT  VARCHAR(2),          ")
			.append("   CONSTRAINT IDX_SSO_ACLG_PK        ")
			.append("     PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                         ")
			.append(" WITH ( OIDS = FALSE )                     ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 0) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                                 ")
			.append("   LOG_DATE   VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME   VARCHAR(6) NOT NULL, ")
			.append("   SEQ        VARCHAR(8) NOT NULL, ")
			.append("   CASE_TYPE  VARCHAR(2),          ")
			.append("   CASE_RSLT  VARCHAR(2),          ")
			.append("   CASE_USER  VARCHAR(30),         ")
			.append("   CASE_DATA  VARCHAR(500),        ")
			.append("   CONSTRAINT IDX_SSO_AULG_PK            ")
			.append("   PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                       ")
			.append(" WITH ( OIDS = FALSE )                   ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	// MySQL
	public static void createLdapTableIndex_mysql(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                   ")
			.append("   LOG_DATE     VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME     VARCHAR(6) NOT NULL, ")
			.append("   SEQ          VARCHAR(8) NOT NULL, ")
			.append("   USER_ID      VARCHAR(100),        ")
			.append("   USER_NAME    VARCHAR(100),        ")
			.append("   ACCESS_IP    VARCHAR(100),        ")
			.append("   ACCESS_TYPE  VARCHAR(2),          ")
			.append("   ACCESS_SP    VARCHAR(100),        ")
			.append("   ACCESS_BR    VARCHAR(2),          ")
			.append("   ACCESS_RSLT  VARCHAR(2),          ")
			.append("   CONSTRAINT IDX_SSO_ACLG_PK        ")
			.append("     PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                         ")
			.append(" COLLATE='utf8_general_ci'                 ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 1051) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                                 ")
			.append("   LOG_DATE   VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME   VARCHAR(6) NOT NULL, ")
			.append("   SEQ        VARCHAR(8) NOT NULL, ")
			.append("   CASE_TYPE  VARCHAR(2),          ")
			.append("   CASE_RSLT  VARCHAR(2),          ")
			.append("   CASE_USER  VARCHAR(30),         ")
			.append("   CASE_DATA  VARCHAR(500),        ")
			.append("   CONSTRAINT IDX_SSO_AULG_PK            ")
			.append("   PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                       ")
			.append(" COLLATE='utf8_general_ci'               ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	// SQL Server
	public static void createLdapTableIndex_sqlserver(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                   ")
			.append("   LOG_DATE     VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME     VARCHAR(6) NOT NULL, ")
			.append("   SEQ          VARCHAR(8) NOT NULL, ")
			.append("   USER_ID      VARCHAR(100),        ")
			.append("   USER_NAME    VARCHAR(100),        ")
			.append("   ACCESS_IP    VARCHAR(100),        ")
			.append("   ACCESS_TYPE  VARCHAR(2),          ")
			.append("   ACCESS_SP    VARCHAR(100),        ")
			.append("   ACCESS_BR    VARCHAR(2),          ")
			.append("   ACCESS_RSLT  VARCHAR(2),          ")
			.append("   CONSTRAINT IDX_SSO_ACLG_PK        ")
			.append("     PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                         ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != 3701) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                                 ")
			.append("   LOG_DATE   VARCHAR(8) NOT NULL, ")
			.append("   LOG_TIME   VARCHAR(6) NOT NULL, ")
			.append("   SEQ        VARCHAR(8) NOT NULL, ")
			.append("   CASE_TYPE  VARCHAR(2),          ")
			.append("   CASE_RSLT  VARCHAR(2),          ")
			.append("   CASE_USER  VARCHAR(30),         ")
			.append("   CASE_DATA  VARCHAR(500),        ")
			.append("   CONSTRAINT IDX_SSO_AULG_PK            ")
			.append("   PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ) ")
			.append(" )                                       ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	public static void createLdapTableIndex_tibero(String dbDriver, String dburl, String dbusr, String dbpwd, String dbtsp) throws Exception
	{
		Class.forName(dbDriver);
		Connection conn = DriverManager.getConnection(dburl, dbusr, dbpwd);
		PreparedStatement pstmt = null;

		try {
			StringBuffer query01 = new StringBuffer();
			query01.append("DROP TABLE SSO_ACLG ");

			pstmt = conn.prepareStatement(query01.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		String tablespace = "";
		if (!dbtsp.isEmpty()) {
			tablespace = " TABLESPACE " + dbtsp;
		}

		StringBuffer query02 = new StringBuffer();
		query02.append("CREATE TABLE SSO_ACLG ")
			.append(" (                                      ")
			.append("   LOG_DATE     VARCHAR2(8 BYTE),       ")
			.append("   LOG_TIME     VARCHAR2(6 BYTE),       ")
			.append("   SEQ          VARCHAR2(8 BYTE),       ")
			.append("   USER_ID      VARCHAR2(100 BYTE),     ")
			.append("   USER_NAME    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_IP    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_TYPE  VARCHAR2(2 BYTE),       ")
			.append("   ACCESS_SP    VARCHAR2(100 BYTE),     ")
			.append("   ACCESS_BR    VARCHAR2(2 BYTE),       ")
			.append("   ACCESS_RSLT  VARCHAR2(2 BYTE)        ")
			.append(" )                                      ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query02.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;
		
		StringBuffer query03 = new StringBuffer();
		query03.append("ALTER TABLE SSO_ACLG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_ACLG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query03.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		try {
			StringBuffer query13 = new StringBuffer();
			query13.append("DROP TABLE SSO_AULG ");

			pstmt = conn.prepareStatement(query13.toString());
			pstmt.executeUpdate();
			pstmt.close();
			pstmt = null;
		}
		catch (SQLException e) {
			if (e.getErrorCode() != -7071) {
				throw new Exception(e.getMessage());
			}
			pstmt.close();
			pstmt = null;
		}

		StringBuffer query14 = new StringBuffer();
		query14.append("CREATE TABLE SSO_AULG ")
			.append(" (                               ")
			.append("   LOG_DATE   VARCHAR2(8 BYTE),  ")
			.append("   LOG_TIME   VARCHAR2(6 BYTE),  ")
			.append("   SEQ        VARCHAR2(8 BYTE),  ")
			.append("   CASE_TYPE  VARCHAR2(2 BYTE),  ")
			.append("   CASE_RSLT  VARCHAR2(2 BYTE),  ")
			.append("   CASE_USER  VARCHAR2(30 BYTE), ")
			.append("   CASE_DATA  VARCHAR2(500 BYTE) ")
			.append(" )                               ")
			.append(tablespace)
			.append(" PCTUSED    0                           ")
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   1                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            )                           ")
			.append(" LOGGING                                ")
			.append(" NOCOMPRESS                             ")
			.append(" NOCACHE                                ")
			.append(" NOPARALLEL                             ")
			.append(" MONITORING                             ");

		pstmt = conn.prepareStatement(query14.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		StringBuffer query15 = new StringBuffer();
		query15.append("ALTER TABLE SSO_AULG ADD ( ")
			.append(" CONSTRAINT IDX_SSO_AULG_PK             ")
			.append(" PRIMARY KEY (LOG_DATE, LOG_TIME, SEQ)  ")
			.append(" USING INDEX                            ")
			.append(tablespace)
			.append(" PCTFREE    10                          ")
			.append(" INITRANS   2                           ")
			.append(" MAXTRANS   255                         ")
			.append(" STORAGE    (                           ")
			.append("             INITIAL          1M        ")
			.append("             MINEXTENTS       1         ")
			.append("             MAXEXTENTS       UNLIMITED ")
			.append("             PCTINCREASE      0         ")
			.append("             BUFFER_POOL      DEFAULT   ")
			.append("            ))                          ");

		pstmt = conn.prepareStatement(query15.toString());
		pstmt.executeUpdate();
		pstmt.close();
		pstmt = null;

		conn.close();
	}

	private static String readPassword(String format) throws Exception
	{
		String sInput = "";

		while (true) {
			Console console = System.console();
			console.printf(format);
			console.printf("> ");
			char[] pwdChars = console.readPassword();
			sInput = new String(pwdChars);

			if (sInput.equals("")) {
				String sCancel = "";

				Scanner scanner2 = new Scanner(System.in);
				System.out.printf("\nCancel Input (Y/N) ? ");
				sCancel = scanner2.nextLine();

				if (sCancel.equalsIgnoreCase("Y")) {
					throw new Exception("Cancel Input");
				}
			}
			else {
				break;
			}
		}

		return sInput;
	}

	private static String readLine(String format, boolean required) throws Exception
	{
		String sInput = "";

		while (true) {
			Scanner scanner = new Scanner(System.in);
			System.out.printf(format);
			System.out.printf("> ");
			sInput = scanner.nextLine().trim();

			if (sInput.equals("cancel")) {
				String sCancel = "";

				Scanner scanner2 = new Scanner(System.in);
				System.out.printf("\nCancel Input (Y/N) ? ");
				sCancel = scanner2.nextLine().trim();

				if (sCancel.equalsIgnoreCase("Y"))
					throw new Exception("Cancel Input");
			}
			else if (sInput.equals("") && required) {
				continue;
			}
			else {
				break;
			}
		}

		return sInput;
	}

	private static void outPrint(String format)
	{
		System.out.printf(format);
	}

	public static void main(String[] args)
	{
		try {
			outPrint("\n");
			outPrint("==============================================\n");
			outPrint("  Product   : " + SSOConfig.getTOE() + "\n");
			outPrint("  Version   : " + SSOConfig.getDetailVersion() + "\n");
			outPrint("  Component : " + SSOConfig.getElementVersion() + "\n");
			outPrint("  Developer : Dreamsecurity Co.,Ltd.\n");
			outPrint("==============================================\n");

			outPrint("\n>>> Start Create Magic SSO Table/Index/Sequence (Cancel: \"cancel\" Input)\n");

			String dbUseYN = "Y";

			String ldapUseYN = readLine("\nUse LDAP : (Y)es / (N)o ?  default) No\n", false);
			if (ldapUseYN.equals("")) {
				ldapUseYN = "N";
			}

			if (ldapUseYN.equalsIgnoreCase("Y")) {
				dbUseYN = readLine("\nUse Database : (Y)es / (N)o ?  default) No\n", false);
				if (dbUseYN.equals("")) {
					dbUseYN = "N";
				}
			}

			if (dbUseYN.equalsIgnoreCase("N")) {
				outPrint("\n>>> Magic SSO - Not Use Database !!!\n\n");
				return;
			}

			String dbDriver = readLine("\nEnter DB Driver Class Name : default) oracle.jdbc.driver.OracleDriver\n", false);
			if (dbDriver.equals("")) {
				dbDriver = "oracle.jdbc.driver.OracleDriver";
			}

			String dbUrl = readLine("\nEnter Database Connection URL : ex) jdbc:oracle:thin:@192.168.10.2:1521:ORASID\n", true);
			String dbUsr = readLine("\nEnter Database Connection User Name : \n", true);
			String dbPwd = readPassword("\nEnter Database Connection User Password : \n");
			String dbTsp = readLine("\nEnter Database Tablespace Name : \n", false);

			if (ldapUseYN.equalsIgnoreCase("Y")) {
				if (dbDriver.indexOf("cubrid") >= 0) {
					createSequence_cubrid(dbDriver, dbUrl, dbUsr, dbPwd);
					createLdapTableIndex_cubrid(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
				else if (dbDriver.indexOf("postgresql") >= 0) {
					createSequence_postgresql(dbDriver, dbUrl, dbUsr, dbPwd);
					createLdapTableIndex_postgresql(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
				else if (dbDriver.indexOf("mysql") >= 0) {
					createSequence_mysql(dbDriver, dbUrl, dbUsr, dbPwd);
					createLdapTableIndex_mysql(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
				else if (dbDriver.indexOf("sqlserver") >= 0) {
					createSequence_sqlserver(dbDriver, dbUrl, dbUsr, dbPwd);
					createLdapTableIndex_sqlserver(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
				else if (dbDriver.indexOf("tibero") >= 0) {
					createSequence_tibero(dbDriver, dbUrl, dbUsr, dbPwd);
					createLdapTableIndex_tibero(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
				else {
					createSequence(dbDriver, dbUrl, dbUsr, dbPwd);
					createLdapTableIndex(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
			}
			else {
				if (dbDriver.indexOf("cubrid") >= 0) {
					createSequence_cubrid(dbDriver, dbUrl, dbUsr, dbPwd);
					createTableIndex_cubrid(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
				else if (dbDriver.indexOf("postgresql") >= 0) {
					createSequence_postgresql(dbDriver, dbUrl, dbUsr, dbPwd);
					createTableIndex_postgresql(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
				else if (dbDriver.indexOf("mysql") >= 0) {
					createSequence_mysql(dbDriver, dbUrl, dbUsr, dbPwd);
					createTableIndex_mysql(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
				else if (dbDriver.indexOf("sqlserver") >= 0) {
					createSequence_sqlserver(dbDriver, dbUrl, dbUsr, dbPwd);
					createTableIndex_sqlserver(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
				else if (dbDriver.indexOf("tibero") >= 0) {
					createSequence_tibero(dbDriver, dbUrl, dbUsr, dbPwd);
					createTableIndex_tibero(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
				else {
					createSequence(dbDriver, dbUrl, dbUsr, dbPwd);
					createTableIndex(dbDriver, dbUrl, dbUsr, dbPwd, dbTsp);
				}
			}

			outPrint("\n>>> Magic SSO Table/Index/Sequence - Create Complete !!!\n\n");
		}
		catch (Exception e) {
			e.printStackTrace();
			outPrint("\nMagic SSO Table/Index/Sequence - Create Exception : " + e.getMessage() + "\n\n");
		}
	}
}