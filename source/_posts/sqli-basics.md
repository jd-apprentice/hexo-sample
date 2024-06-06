---
title: SQLi Basics
date: 2024-06-05 22:52:25
tags: [research, Web Applications]
categories: research
keywords: 'research, Web Applications, exploits'
description: I took inspiration from researching this topic from one of the recent machines that I wrote a writeup for, which you can find [here](https://dan-feliciano.com/writeups/trusted/) (you can probably get the interpretation from the name of the chain). The topic that I wanted to delve into today was the idea of Domain and Forest Trusts in an Active Directory environment. I tried getting a little creative with Lucidchart, as you'll see in the images to follow.
cover: /images/research/sqli-basics/sqli.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

SQL Injection is a web security vulnerability that essentially allows an attacker to maliciously query a database through an input form. Otherwise known as SQLi, SQL injection thus can allow the attacker to view data from within an SQL database that they would normally should not be able to view.

# Introduction

When I was progressing through my research into exploits, I came across various different forms of SQL injections and how they specifically affect the web services from where they are hosted. While they can vary from web application to web application, the practicality of the information you are attempting to retrieve is generally the same. In many cases, we are hoping to reveal information about databases, following that are tables, and finally following that are entries.

But that being said, what exact information are we actually trying to receive? For pen-tests or red teaming activities, there are different assets that we can find that can allow us to access other services. For threat actors and TTPs, some of the assets to be compromised are the same. The only difference is that those same threat actors are using this information to compromise pertinent user data with the intent to produce a negative effect on the organization.

In most cases, these affect databases that are directly connected to a web form where the input form originates. Their input can me modified in order to query the entirety of a database, specific tables, or specific entries where data is housed.

![](/images/research/sqli-basics/b.png)

In order for a web-application to retrieve information from a database, it generally needs to utilize some query to retrieve contents from a specific part of the database. This can be utilized in use cases such as matching the input with valid contents in the database or in a search parameter to provide similar content names of a field search. 

# Input Methodology

The general methodology to SQLi is that certain SQL characters such as `;` or `'` can cause the input to be split. While these can cause errors in the SQL statement altogether, they can also cause SQL database contents to be leaked to the client navigating to the website.

In most cases aside from data exfiltration, attackers can use SQLi to compromise the entirety of an underlying server or the back-end of the server itself (or even web-service attacks such as Denial-of-Service).

Now how does this exactly occur? Well, in most cases, SQLi occurs within the `WHERE` statement of a `SELECT` query, which is the specific part of the query that is attempting to retrieve data from a database. That being said, it can also occur in other locations that host different queries. This can be found in:

* `SELECT` and `ORDER BY` clauses.
* `INSERT` and subsequent inserted variables.
* `SELECT` statements that reside within a specific table or column.
* `UPDATE` calls, which the values are interchanged within a `WHERE` clause.
* `UNION SELECT` statements, which collect a group of data.

The list can go on and on. In most cases, these all require general knowledge of specifically how the request is being handled before it is sent to the backend SQL database. When we are attempting to understand the query being used, we need to ask ourselves a few questions.

* Is the application handling data from a specific database that retrieves hidden data?
* While we may not be able to receive an output, can we produce a valid request using a wildcard? (Blind SQLi)
* Is the query allowing us to select multiple categories or tables? (UNION SELECT attacks)

We'll take a look at more in-depth SQLi attacks in the future, such as Blind SQLi or UNION select attacks. For this specific post we'll focus on basic SQLi methodology.

# Basic Example SQLi

Let's say for instance we have access to a website with the following URL parameter. This was accessed by clicking on the only hyperlink on the page, which gave us an output of the entries that we have access to below (Note that this website section does not actually exist on this webpage).

> `http://dan-feliciano.com/section?entry_name=red`

* This results in the following sentence being output to the website page in a notepad-like format.

```
Entries for RED.

Entry 1 - RED
Entry 2 - RED
```

* On the backend, the SQL table `COLORS` is the table that is being used for data on this webpage. An example table is provided below to illustrate what this could look like.*

| TABLE: COLORS | entry_color | id  | available |
| ------------- | ----------- | --- | --------- |
| Entry 1       | RED         | 1   | 1         |
| Entry 2       | RED         | 2   | 1         |
| Entry 3       | BLUE        | 3   | 1         |
| Entry 4       | BLUE        | 4   | 1         |
| Entry 5       | YELLOW      | 5   | 0         |
| Entry 6       | YELLOW      | 6   | 0         |
| Entry 7       | RED         | 7   | 0         |

* In order to receive this specific entry, a query will be sent to the database in order to retrieve the data in that entry. The SQL query that is sent to the database in our case is the following:

```
SELECT * FROM sections WHERE entry_color = 'RED' AND available = '1'
```

This SQL query consists of the following data (to which the database will interpret):

* `SELECT * FROM sections` will select all column/row entries from the `sections` table.
* `WHERE entry_color = 'RED'` is the first argument, saying to only output entries within the `entry_name` column with the entry value 'RED'.
* `AND available = 1` is another argument that says to also only include entries with an `available` value of 1.

If we put all of this together based on the table that was provided based on the backend above, then the entry that will be given to us are `Entries 1 and 2`. To keep in-line with the example, let's say that we're unable to access any other parameters by just editing the URL and retrieving the other parameters. The only space we have access to is this webpage with static entries.

The main bar in our specific situation is the `available` value. As you may have noticed, the query that is being sent to the database will only return entries that have an `available` value of 1. This means that all values that are output to the webpage from the database will only include `Entries 1 and 2` and will NOT include `Entry 7`. The other entries are also barred from the output since they do not include an `entry_color` value of 'RED'.

In order to circumvent this in a basic scenario, we could construct an input into the URL parameter to exploit this simple weakness and exfil not just `Entry 7`, but all entries as a result.

>`http://dan-feliciano.com/section?entry_name=red'+OR+1=1--`

In this entry, we are essentially saying that we want all entries with an `entry_name` of 'RED' - OR we would all entries where `1=1`, which is always true.

```
SELECT * FROM sections WHERE entry_color = 'RED' AND available = '1' OR 1=1
```

Due to the conditional `OR` statement being fulfilled, the `SELECT` query will instead return all of the entries. `SELECT * FROM sections`

```
Entries for RED.

Entry 1 - RED
Entry 2 - RED
Entry 3 - BLUE
Entry 4 - BLUE
Entry 5 - YELLOW
Entry 6 - YELLOW
Entry 7 - RED
```

As denoted above, this has returned all of the entries and we have successfully exploited the SQLi vulnerability.

Be wary of issues as these, as in some cases our queries may come into contact with a `DELETE` or an `UPDATE` statement, meaning that they could accidentally delete or alter data. It's important to take into consideration what the result of our query will do, as we want to circumvent harmful changes like these. When red-teaming, ensure that you understand the queries that will be sent to the database and that you keep as low of a profile as possible.

Big thanks to PortSwigger (the creators of Burpsuite), as this post was inspired by the documentation they have as I continue to progress through all of their web-app labs.

![](/images/research/sqli-basics/c.png)

This was a practice web-page implementation on what I'd like to see in my research. I expect to research more into SQLi and other web-application attacks in the future.

# Resources

https://portswigger.net/web-security/sql-injection
https://owasp.org/www-community/attacks/SQL_Injection
https://www.imperva.com/learn/application-security/sql-injection-sqli/

