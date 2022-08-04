import os
import sys

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

from datetime import datetime
import pytz

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# INDEX ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""

    if request.method == "POST":
        # check whether post request == add_cash / buy / sell
        request_type = request.args.get("form")
        print(request_type)

        # user wants to add cash to their account ~~~~~~~~~~~~~
        if request_type == "add_cash":
            # get amount they wish to top up
            amt_top_up = request.form.get("topup_amt")

            print(amt_top_up)
            try:
                amt_top_up = int(amt_top_up)
            except:
                return apology("top up amount must be positive integer", 400)

            else:
                # check that share_qty input is an int higher than 1
                if amt_top_up < 1:
                    return apology("top up amount must be positive integer", 400)

                # check how much cash the user has      add [0]["cash"] to iterate into list and then dictionary
                remaining_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"] )[0]["cash"]
                new_bal = remaining_cash + amt_top_up

                # update new
                db.execute("UPDATE users SET cash = ? WHERE id = ?", new_bal, session["user_id"])

                return redirect("/")


        # user wants to buy a stock ~~~~~~~~~~
        elif request_type == "buy":
            # check if input is empty
            if not request.form.get("symbol"):
                return apology("must provide ticker symbol", 400)

            elif not request.form.get("shares"):
                return apology("must provide share quantity", 400)

            # get symbol and trade qty
            else:
                input_symbol = request.form.get("symbol_to_buy")
                share_qty = request.form.get("shares")
                print(f"User wants to buy {share_qty} shares of {input_symbol}")

                # call buy function
                buy_status = buy_function(input_symbol, share_qty)

                print (buy_status)
                if buy_status == 1:
                    return apology("share quantity must be positive integer", 400)
                elif buy_status == 2:
                    return apology("provided ticker symbol is invalid", 400)
                elif buy_status == 3:
                    return apology("share quantity must be positive integer", 400)
                elif buy_status == 4:
                    return apology("insufficient remaining cash", 400)
                else:
                    # buy status = 0 (no problems), return to index page
                    return redirect("/")

        # user wants to sell a stock ~~~~~~~~~~~~
        else:
            # check if input is empty
            if not request.form.get("symbol"):
                return apology("must provide ticker symbol", 400)

            elif not request.form.get("shares"):
                return apology("must provide share quantity", 400)

            # get symbol and trade qty
            else:
                input_symbol = request.form.get("symbol_to_sell")
                share_qty = request.form.get("shares")
                print(f"User wants to sell {share_qty} shares of {input_symbol}")

                # make a list of user's stock holdings using MAKE STOCK LIST function
                stock_list = make_stock_list()
                print(stock_list)

                # call SELL function
                sell_status = sell_function(input_symbol, share_qty, stock_list)
                print (sell_status)
                if sell_status == 1:
                    return apology("share quantity must be positive integer", 400)
                elif sell_status == 2:
                    return apology("provided ticker symbol is invalid", 400)
                elif sell_status == 3:
                    return apology("share quantity must be positive integer", 400)
                elif sell_status == 4:
                    return apology("attempted to sell more than available", 400)
                else:
                    # sell status = 0 (no problems), # return to index page
                    return redirect("/")

    # default page that they view ~~~
    else:
        # For displaying remaining cash balance. Get remaining cash amount from 'users' table
        remaining_cash = int( db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"] )

        # For displaying total portfolion value (pt 1/2) where we get (sum of total value of all stocks)
        all_stock_total_val = 0

        # search database to return a list with the following info
        #   -all stocks user owns --> ticker symbol, stock name, stock quantity
        stock_holdings = db.execute("SELECT ROW_NUMBER() OVER (ORDER BY stock_name) AS sn, stock_name, stock_symbol, holding_qty FROM holdings WHERE person_id = ?", session["user_id"])

        # for each stock...
        for stock in stock_holdings:
            # add a 'current price' key-value pair.Use lookup function with ticker symbol. add ["price"] behind to get price from dict
            stock["current_price"] = lookup(stock["stock_symbol"])["price"]

            # add a 'Total_value_of_stock' key-value pair by calculating
            stock["total_value"] =  round(stock["current_price"] *  stock["holding_qty"], 2)
            all_stock_total_val += stock["total_value"]
            print(f"all stocks total val: {all_stock_total_val}")
            print(stock)


        # For displaying total portfolion value (pt 2/2). Add remaining cash and all stock total value. limit to 2 decimal place
        portfolio_val = round(all_stock_total_val + remaining_cash, 2)

        return render_template("/index.html", stock_holdings=stock_holdings, remaining_cash=remaining_cash, portfolio_val = portfolio_val)


# BUY ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User requested a quote via POST (after submitting stock symbol)
    if request.method == "POST":

        # check if input is empty
        if not request.form.get("symbol"):
            return apology("must provide ticker symbol", 400)

        elif not request.form.get("shares"):
            return apology("must provide share quantity", 400)

        else:
            # get inputs
            input_symbol = request.form.get("symbol")
            share_qty = request.form.get("shares")

            # call buy function
            buy_status = buy_function(input_symbol, share_qty)
            print (buy_status)
            if buy_status == 1:
                return apology("share quantity must be positive integer", 400)
            elif buy_status == 2:
                return apology("provided ticker symbol is invalid", 400)
            elif buy_status == 3:
                return apology("share quantity must be positive integer", 400)
            elif buy_status == 4:
                return apology("insufficient remaining cash", 400)
            else:
                # buy status = 0 (no problems)
                return redirect("/")

    else:
        return render_template("/buy.html")

# BUY ~~~~~
def buy_function(input_symbol, share_qty):
    # use lookup function to return stock details (name, price, symbol)
    stock_info = lookup(input_symbol)
    print(stock_info)

    
    # try casting share_qty to int, if can't means that user messed with input
    try:
        share_qty = int(share_qty)
        print("no problems casting to int")

    # return error number cause it's not an int
    except:
        return 1

    # if provided ticker symbol is invalid
    else:
        if (stock_info == None):
            return 2

        # if share quantity is lesser than 1
        elif share_qty < 1:
            return 3

        else:
            # check how much money the purchase of stock is
            buy_cost = stock_info["price"] * share_qty
            print(f'stock price: {stock_info["price"]}')
            # print(f"share qty: {share_qty}")
            # print(f"total buy cost: {buy_cost}")

            # check how much cash the user has      add [0]["cash"] to iterate into list and then dictionary
            remaining_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"] )[0]["cash"]
            # print(f'user id:{ session["user_id"]}' )
            print(remaining_cash)

            # if user's remaining cash is not enough for purchase
            if (remaining_cash < buy_cost):
                return 4

            # if user has remaining cash
            else:
                # get rdam time zone
                rdam_time = pytz.timezone("Europe/Amsterdam")
                # get date and time + format it
                date_time = datetime.now(rdam_time).strftime("%d/%m/%Y, %H:%M:%S")
                print(f"datetime:{date_time}, get date time successful")

                # fill 'transaction' table
                db.execute("INSERT INTO transactions (person_id, datetime, trade, stock_name, stock_symbol, stock_price, quantity_traded, total_amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", session["user_id"], date_time, "buy", stock_info["name"], stock_info["symbol"], stock_info["price"], share_qty, buy_cost)
                print("insert into transactions successful")

                # edit cash in 'users' table
                db.execute("UPDATE users SET cash = ? WHERE id = ?", (remaining_cash - buy_cost), session["user_id"])
                print("edit user's cash successful")

                # edit user holdings
                # first, check whether user already holds a particular stock        # take note of how check for string is passed into query. Notice how the brackets are used

                existing_holdings = db.execute("SELECT holding_qty FROM holdings WHERE person_id = ? AND stock_symbol = ""?""", session["user_id"], stock_info["symbol"] ) #[0]["holding_qty"]
                #can't add '[0]["holding_qty"] cause if the list is empty, there is no ["holding_qty to iterate into]
                print(f"Existing holding quantity: {existing_holdings}")
                print("check existing holdings - successful")

                # if there are existing holdings
                if existing_holdings:
                    print("has existing holdings")
                    # iterate into list and then key-value pair and get the number of holdings. convert to int
                    existing_holdings = int(existing_holdings[0]["holding_qty"])
                    print(f"existing holdings: {existing_holdings}")
                    updated_holdings = existing_holdings + share_qty
                    print(f"updated holdings: {updated_holdings}")
                    db.execute("UPDATE holdings SET holding_qty = ? WHERE person_id = ? AND stock_symbol = ?", updated_holdings, session["user_id"], stock_info["symbol"])
                    print("update holdings successful (route 1)")

                    return 0

                # if there are no existing holdings
                else:
                    print("has NO existing holdings")
                    db.execute("INSERT INTO holdings (person_id, stock_name, stock_symbol, holding_qty) VALUES (?, ?, ?, ?)", session["user_id"], stock_info["name"], stock_info["symbol"], share_qty)
                    print("update holdings successful (route 2)")

                    return 0

# HISTORY ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get history of individual's transaction
    transact_hist = db.execute("SELECT ROW_NUMBER() OVER (ORDER BY datetime DESC) AS sn, stock_symbol, datetime, trade, stock_price, quantity_traded, total_amount FROM transactions WHERE person_id = ? ORDER BY datetime DESC", session["user_id"])

    return render_template("/history.html", transact_hist=transact_hist)

# LOGIN ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")


    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

# LOGOUT ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

# QUOTE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User requested a quote via POST (after submitting stock symbol)
    if request.method == "POST":
        input_symbol = request.form.get("symbol")

        # check if input is empty
        if not request.form.get("symbol"):
            return apology("must provide ticker symbol", 400)

        # else if input is not empty...
        else:
           # use lookup function to return stock details (name, price, symbol)
            stock_info = lookup(input_symbol)

            print(f"{stock_info}")

            # if provided ticker symbol is invalid
            if (stock_info == None):
                return apology("provided ticker symbol is invalid", 400)

            # if stock info does not return empty
            else:
                return render_template("/quoted.html", stock_info=stock_info)

    return render_template("/quote.html")

# REGISTER ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

    # if user does not input username
        if not request.form.get("username"):
            return apology("must provide username", 400)

    # if user does not input password
        elif not request.form.get("password"):
            return apology("must provide password", 400)

    # if user does not input confirmation for password
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

    # if all input provided...
        else:
            # get all username, password and confirmation of password
            input_username = request.form.get("username")
            input_pass = request.form.get("password")
            confirm_pass = request.form.get("confirmation")

            # check if username is taken
            username_exists = db.execute("SELECT COUNT(*) as count FROM users WHERE username = ?", input_username)[0]["count"]
            print(username_exists)


            # if 1 means that there's already a user with this name
            if username_exists == 1 :
                return apology("username already exists", 400)

            # if password and password confirmation does not match
            elif (input_pass != confirm_pass):
                return apology("passwords do not match", 400)

    # if password does not meet requirements
    #   -pw len < 8
    #   -pw length doesn't have different characters
    #   elif

        # if username is valid & not a duplicate, pw matches and meets requirement
        # hash function
            else:
                hashed_pw = generate_password_hash(confirm_pass, method='pbkdf2:sha256', salt_length=8)

        # put username and hashed passowrd into sql database
                db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", input_username, hashed_pw)

        # check in sql that cash for new user is 10k    (it works!)
        # if everything is successful, redirect user to login page
                return redirect("/login")

    # Since by default, they haven't submitted anything, this will be the page that is directed to
    else:
        return render_template("register.html")

# SELL ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # make a list of user's stock holdings using MAKE STOCK LIST function
    stock_list = make_stock_list()
    print(stock_list)

    # User reached route via POST (as by submitting a form via POST)

    if request.method == "POST":
        # check if input is empty
        if not request.form.get("symbol"):
            return apology("must provide ticker symbol", 400)

        elif not request.form.get("shares"):
            return apology("must provide share quantity", 400)

        else:
            # get user's inputs for stock and quantity
            selected_symbol = request.form.get("symbol")
            sell_qty = request.form.get("shares")

            # call SELL function
            sell_status = sell_function(selected_symbol, sell_qty, stock_list)

            print (sell_status)
            if sell_status == 1:
                return apology("share quantity must be positive integer", 400)
            elif sell_status == 2:
                return apology("provided ticker symbol is invalid", 400)
            elif sell_status == 3:
                return apology("share quantity must be positive integer", 400)
            elif sell_status == 4:
                return apology("attempted to sell more than available", 400)
            else:
                # sell status = 0 (no problems), return to sell page
                return redirect("/")

    # default: start page with list
    else:
        return render_template("sell.html", stock_list=stock_list)

# ~~~~~~~~~~
def make_stock_list():
    # search database to return a list with dictionary with each stock they hold
    stock_holdings = db.execute("SELECT stock_name, stock_symbol, holding_qty FROM holdings WHERE person_id = ?", session["user_id"])

    list_of_stocks = []

    for stock in stock_holdings:
        to_append = stock["stock_symbol"]
        list_of_stocks.append(to_append)

    return list_of_stocks

# ~~~~~~~~~~
def sell_function(selected_symbol, sell_qty, stock_list):

# try casting share_qty to int, if can't means that user messed with input
    try:
        sell_qty = int(sell_qty)
    except:
        return 1

    else:
        # if provided ticker symbol does not match any in stock_list list (user messed with html on web)
        if (selected_symbol not in stock_list):
            return 2

        # check that share_qty input is an int higher than 1
        elif sell_qty < 1:
            return 3

        # check if individual tried to sell more than they have
        else:
            # get individual's available stock holding quantity
            qty_avail = db.execute("SELECT holding_qty FROM holdings WHERE person_id = ? AND stock_symbol = ""?"" ", session["user_id"], selected_symbol)[0]["holding_qty"]
            print(f"qty held: {qty_avail}")

            if (sell_qty > qty_avail):
                return 4

            # all checks completed, can update transaction now
            else:
                # get current stock price using lookup function and iterate into name key-value pair in dict
                stock_info = lookup(selected_symbol)
                # calc sell value
                sell_val = stock_info["price"] * sell_qty

                # UPDATE TRANSACTIONS

                # get rdam time zone
                rdam_time = pytz.timezone("Europe/Amsterdam")
                # get date and time + format it
                date_time = datetime.now(rdam_time).strftime("%d/%m/%Y, %H:%M:%S")
                print(f"datetime:{date_time}, get date time successful")

                # fill 'transaction' table
                db.execute("INSERT INTO transactions (person_id, datetime, trade, stock_name, stock_symbol, stock_price, quantity_traded, total_amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", session["user_id"], date_time, "sell", stock_info["name"], stock_info["symbol"], stock_info["price"], sell_qty, sell_val)
                print("insert into transactions successful")


                # UPDATE USER'S CASH BALANCE
                # check how much cash the user has      add [0]["cash"] to iterate into list and then dictionary
                remaining_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"] )[0]["cash"]

                # update cash balance
                db.execute("UPDATE users SET cash = ? WHERE id = ?", (remaining_cash + sell_val), session["user_id"])
                print("edit user's cash successful")


                # UPDATE HOLDINGS
                print(f"qty avail: {qty_avail}")
                print(f"sell qty: {sell_qty}")
                db.execute("UPDATE holdings SET holding_qty = ? WHERE person_id = ? AND stock_symbol = ""?""", (qty_avail - sell_qty), session["user_id"], stock_info["symbol"] )
                updated_holding_qty = db.execute("SELECT holding_qty FROM holdings WHERE person_id = ? AND stock_symbol = ""?"" ", session["user_id"], selected_symbol)[0]["holding_qty"]
                print(f"updated holdings: {updated_holding_qty}")
                print("check existing holdings - successful")

                # if there are no existing holdings
                if (qty_avail - sell_qty) == 0:
                    print("has existing holdings")
                    # iterate into list and then key-value pair and get the number of holdings. convert to int
                    db.execute("DELETE FROM holdings WHERE person_id = ? AND stock_symbol = "" ? """, session["user_id"], stock_info["symbol"])
                    print("delete stock from user's holdings where qty is 0 (route 1)")

                    return 0

                # if there are existing holdings
                else:
                    return 0


# CHANGE PASSWORD~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
@app.route("/change_pass", methods=["GET", "POST"])
@login_required
def change_pass():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # if any inputs are missing
        if not request.form.get("old_pass"):
            return apology("must provide current password", 403)

        elif not request.form.get("new_pass"):
            return apology("must provide new password", 403)

        elif not request.form.get("cfm_pass"):
            return apology("must confirm new password", 403)

        # if all inputs are provided
        else:
            # Get all user inputs
            old_pw = request.form.get("old_pass")
            new_pw = request.form.get("new_pass")
            cfm_pw = request.form.get("cfm_pass")

            # check if old password is correct
            # Query database for user details (including hash)
            user_details = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

            # if current password and input for 'old pw' does not match
            if len(user_details) != 1 or not check_password_hash(user_details[0]["hash"], old_pw):
                return apology("invalid current password", 403)

            # old password matches
            elif (new_pw != cfm_pw):
                return apology("confirmation password does not match new password", 403)

            # if old password matches and confirmation password passed
            else:
                print(f"passwords match > {new_pw} || {cfm_pw}")

                # generate hash for user's new password
                hash = generate_password_hash(cfm_pw, method='pbkdf2:sha256', salt_length=8)

                # update user's details in database
                db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, session["user_id"])

                # Redirect user to home page
                return redirect("/change_pass")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("change_pass.html")


# RESET ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
@app.route("/reset", methods=["GET", "POST"])
@login_required
def reset():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Get all user inputs
        user_pw_input = request.form.get("password")

        # Query database for user details (including hash)
        user_details = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # if pw input field is empty
        if not user_pw_input:
            return apology("must provide password", 403)

        # if passwords do not match
        elif len(user_details) != 1 or not check_password_hash(user_details[0]["hash"], user_pw_input):
            return apology("invalid password", 403)

        # if password matches
        else:
            print("pw match")

            # reset cash to 10000
            db.execute("UPDATE users SET cash = 10000 WHERE id = ?", session["user_id"])

            # delete all transactions
            db.execute("DELETE FROM transactions WHERE person_id = ?", session["user_id"])

            # delete all holdings
            db.execute("DELETE FROM holdings WHERE person_id = ?", session["user_id"])

            # Redirect user to home page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("reset.html")