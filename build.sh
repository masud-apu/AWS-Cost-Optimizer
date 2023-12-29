pwd
ls
pip install -r requirments.txt
python manage.py makemigrations
python manage.py collectstatic --no-input
python manage.py migrate