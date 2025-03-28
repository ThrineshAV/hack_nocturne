1.Setup Instructions
"git clone <repository_url>
cd <repository_folder>
"
2. Create and Activate Virtual Environment
"python -m venv venv    #create environment 
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
"
3.Install Required Dependencies
"pip freeze > requirements.txt
"
4. Check with migrations
"python manage.py makemigrations
python manage.py migrate
"
5. Create Superuser (Admin)
"python manage.py createsuperuser
"
6.Running the Server
"python manage.py runserver
"


