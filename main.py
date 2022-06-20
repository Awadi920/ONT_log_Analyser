import streamlit as st
import pandas as pd
import pickle
from sklearn.preprocessing import LabelEncoder
import time
import streamlit_authenticator as stauth
from pathlib import Path
import os
import sqlite3

# DB Management
conn = sqlite3.connect('data.db')
c = conn.cursor()

#Create user table
def create_usertable():
    c.execute('CREATE TABLE IF NOT EXISTS userstable(username TEXT,password TEXT)')

#Add userneme and password in our DB
def add_userdata(username,password):
    c.execute('INSERT INTO userstable(username,password) VALUES (?,?)',(username,password))
    conn.commit()

#check username and password in DB
def login_user(username,password):
	c.execute('SELECT * FROM userstable WHERE username =? AND password = ?',(username,password))
	data = c.fetchall()
	return data

#Save File
def save_uploaded_file(uploadedfile):
    with open(os.path.join("Saved_File",uploadedfile.name),"wb")as f:
        f.write(uploadedfile.getbuffer())


def main():
    #settings Admin Account
names = ["Mohamed Amine"]
    usernames = ["Admin"]

    # load hashed passwords
    file_path = Path(__file__).parent / "hashed_pw.pkl"
    with file_path.open("rb") as file:
        hashed_passwords = pickle.load(file)

    authenticator = stauth.Authenticate(names, usernames, hashed_passwords,
                                        "log_analyse", "abcdef", cookie_expiry_days=30)

    name, authentication_status, username = authenticator.login("Login", "main")

    #Signup
    Signup = st.sidebar.title('Sign Up')
    if Signup:
        new_user = st.sidebar.text_input('Username :')
        new_passwd = st.sidebar.text_input('Password :', type='password')
        if st.sidebar.button('Create Account.'):
            create_usertable()
            add_userdata(new_user, new_passwd)
            st.sidebar.success("You have successfully created your account")

    #Login
    create_usertable()
    result = login_user(username, new_passwd)

    if authentication_status == False or result == False :
        st.error("Username/password is incorrect")

    if authentication_status  == None or result == None:
        st.warning("Please enter your username and password")

    if authentication_status or result:

        st.markdown("<h2 style='text-align: center; color: white;font-size:52px;'>ONT Log Analyzer </h2>", unsafe_allow_html=True)

        dataset = st.file_uploader("Upload Your File Here :", type=['csv','log','txt'])
        if dataset is not None:
            df = pd.read_table(dataset, sep=" ", header=None)

            save_uploaded_file(dataset)

            names = ["Date", "Time", "Log_id", "Type", "Sub_type", "Level", "VD", "Log_desc", "Rating", "summary", "Audit_id",
                 "Audit_time", "Audit_score", "Audit_report_type", "Critical_count", "High_count", "Medium_count",
                 "Low_count", "Passed_count"]

            df.columns = names

            for i in df.columns:
                df[i] = df[i].astype(str).str.replace('"', '')

            #nettoyage des contenues
            for i in df.columns:
                df[i] = df[i].astype(str).replace(
                    to_replace=['date=', 'time=', 'logid=', 'type=', "sub", 'level=', "vd=", "logdesc=",
                                "auditid=", "audit", "score=", 'auditreport', "criticalcount=", "highcount=",
                                "mediumcount=", "lowcount=", "passedcount="], value='', regex=True)


            #Changement de type des colonnes
            df['Date'] = df.Date.astype(str)
            df['Audit_score'] = df.Audit_score.astype(float)
            for i in ['Critical_count', 'High_count', 'Medium_count', 'Low_count', 'Passed_count']:
                df[i] = df[i].astype('int')

            #Feature Selection Avec Correlation
            df = df.drop(["Log_id"], axis=1)
            df = df.drop(["Audit_id", "Audit_time"], axis=1)

            #Normalisation
            le = LabelEncoder()
            for column in df.columns:
                df[column] = le.fit_transform(df[column])

            #loaded_model ML
            loaded_model = pickle.load(open("C:/Users/Aouadi/Desktop/ONT Streamlit/KNN_trained_model.sav", "rb"))
            prediction = loaded_model.predict(df)
            print(prediction)


            if st.button("Predict"):

                st.write("Please Wait :")
                my_bar = st.progress(0)
                for p in range(100):
                    time.sleep(0.1)
                    my_bar.progress(p + 1)

            #Prediction ML

            # 0
                aa = [i for i in prediction if i != 1]

            # 1
                bb = [i for i in prediction if i != 0]


                if len(aa) > len(bb):
                    st.success("Your Network is in Safe.")
                else:
                    st.error('You Need To Check Your Network Security.')

        #logout
        authenticator.logout("Logout", "main")

if __name__ == '__main__':
    main()