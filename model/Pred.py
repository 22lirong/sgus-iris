from model.DatabasePool import DatabasePool
from config.Settings import Settings

class Pred:
    @classmethod
    def getAllPred(cls):
        dbConn=DatabasePool.getConnection()
        #db_Info = dbConn.connection_id

        cursor = dbConn.cursor(dictionary=True)

        cursor.execute("select * from pred")
        preds = cursor.fetchall()
        #print(f"Connected to {db_Info}");
        
        dbConn.close()
        return preds


    @classmethod
    def getPred(cls, pred_id):
        try:
            dbConn=DatabasePool.getConnection()
            db_Info = dbConn.connection_id
            print(f"Connected to {db_Info}");

            cursor = dbConn.cursor(dictionary=True)
            sql="select * from pred where pred_id = %s"

            cursor.execute(sql, (pred_id, ))
            preds = cursor.fetchall() 

            return preds

        finally:
            dbConn.close()
            print("release connection")




    @classmethod
    def getPredByUser(cls, user_id):
        dbConn=DatabasePool.getConnection()
        #db_Info = dbConn.connection_id

        cursor = dbConn.cursor(dictionary=True)

        sql="select p.*, u.user_name from pred p, user u where u.user_id = p.user_id and p.user_id = %s order by p.pred_id desc"
        cursor.execute(sql, (user_id, ))
        
        preds = cursor.fetchall()
        #print(f"Connected to {db_Info}");
        
        dbConn.close()
        return preds

    
    @classmethod
    def insertPred(cls, user_id, sepal_length, sepal_width, petal_length, petal_width, prediction):
        dbConn = DatabasePool.getConnection()
        cursor = dbConn.cursor(dictionary = True)

        sql = "insert into pred(user_id, sepal_length, sepal_width, petal_length, petal_width, prediction) values (%s, %s, %s, %s, %s, %s)"
        preds = cursor.execute(sql, (user_id, sepal_length, sepal_width, petal_length, petal_width, prediction))
        
        dbConn.commit()
        rows=cursor.rowcount
        #print(cursor.lastrowid)

        dbConn.close()

        return rows


    @classmethod
    def deletePred(cls, pred_id):
        dbConn = DatabasePool.getConnection()
        cursor = dbConn.cursor(dictionary = True)

        sql = "delete from pred where pred_id = %s"
        preds = cursor.execute(sql, (pred_id, ))
        
        dbConn.commit()
        rows=cursor.rowcount

        dbConn.close()

        return rows


