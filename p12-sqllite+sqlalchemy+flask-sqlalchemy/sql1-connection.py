from sqlalchemy import create_engine
db = create_engine('sqlite:///company1.sqlite')

# ispis u konzoli
db.echo = True
conn = db.connect()

# kreiramo tablicu u bazi
conn.execute("""
    CREATE TABLE Employees (
        ID INTEGER PRIMARY KEY,
        Name STRING(100) NOT NULL,
        Birthday DATE NOT NULL
    )""")

# unesimo tri nova zapisa u bazu
conn.execute("INSERT INTO Employees VALUES (NULL, 'Mate Jurić', date('1990-12-06') );")
conn.execute("INSERT INTO Employees VALUES (NULL, 'Ana Horvat', date('1995-09-16') );")
conn.execute("INSERT INTO Employees VALUES (NULL, 'Pero Ždero', date('2000-01-25') );")
for row in conn.execute("SELECT * FROM Employees"):
    print (row)

# vratimo konekciju u "connection pool"
conn.close()