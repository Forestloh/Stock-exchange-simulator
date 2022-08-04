
Different pages for each 50 transaction

SELECT *
FROM transactions
ORDER BY datetime
WHERE person_id = ____
OFFSET ____ ROWS FETCH NEXT ____ ROWS ONLY;





SELECT
ROW_NUMBER()
OVER (ORDER BY stock_symbol) AS sn, stock_symbol, datetime, trade, stock_price, quantity_traded, total_amount
FROM transactions
WHERE person_id = ?
ORDER BY datetime DESC", session["user_id"]



UPDATE users SET cash = ? WHERE id = ?";





SELECT
FROM (SELECT TOP 10 A.*, 0 AS Ordinal
      FROM A
      ORDER BY [Price]) AS A1

UNION ALL

SELECT *
FROM (SELECT TOP 3 A.*, 1 AS Ordinal
      FROM A
      ORDER BY [Name]) AS A2