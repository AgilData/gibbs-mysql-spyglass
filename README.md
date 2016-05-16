![Gibbs Logo](https://github.com/AgilData/gibbs-mysql-spyglass/blob/gh-pages/images/Gibbs-Spyglass.png)
# Gibbs MySQL Spyglass

Ahoy Matey! The Gibbs MySQL Spyglass is a application used to capture application traffic into a MySQL database.  It is designed to be a passive snifer accessing the MySQL client protocol.  Spyglass is deployed as part of AgilData's Gibbs MySQL Advisor Service which provides deep performance and shard safe analysis.   

Database administrators and developers can use Spyglass to capture application traffic to their MySQL databases and submit the output to the Gibbs MySQL Advisor service for a review and scoring of common performance issues, schema and table strucutres and query optimization. 

[![Build Status](https://travis-ci.org/AgilData/gibbs-mysql-spyglass.svg?branch=master)](https://travis-ci.org/AgilData/gibbs-mysql-spyglass)  [![](https://img.shields.io/badge/License-GPL3-green.svg)](https://github.com/agildata/gibbs-mysql-spyglass/blob/master/LICENSE.TXT)

|i686-apple-darwin|i686-unknown-linux-gnu|x86_64-apple-darwin|x86_64-unknown-linux-gnu|x86_64-unknown-linux-musl|
|:---------------:|:--------------------:|:-----------------:|:----------------------:|:-----------------------:|

# Installation
```
curl -s https://raw.githubusercontent.com/AgilData/gibbs-mysql-spyglass/master/install.sh | bash
```

# Developer Prerequisites
https://www.rustup.rs/


