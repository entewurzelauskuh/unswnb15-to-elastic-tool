# unswnb15-to-elastic-tool
A simple script for importing the data from the [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
dataset into your elasticsearch instance with a suggested index mapping in JSON format.

### A note beforehand

Please note: This script will **NOT** create an elasticsearch index for you. You need to do this beforehand yourself.
The suggested elasticsearch mapping used by this script can be found in the
`elasticsearch_unswnb15_index_mapping.json` file.

### How to use this script

Clone this project into a directory. You'll then need to download the UNSW-NB15 CSV files from the official source.
This dataset comes in four separate CSV files (`UNSW-NB15_1.csv` - `UNSW-NB15_4.csv`), which need to be placed in the
data folder of this project.

Next, I recommend using a virtualenv to create a separate python instance besides your default one. To create a
virtualenv, you need to install the package to create one through `sudo apt-get install virtualenv` and create the
environment with `virtualenv <env_name>`. You can then activate it with `source <env_name>/bin/activate` and install
the required packages for this script with `pip install -r requirements.txt`.

Finally, you can run this script with python with `python run.py -u <es_user>
-p <es_password> -i <es_index> [-e <es_host> -p <es_port> -m <http_method> -l]`. See `python run.py -h` for a detailed
explanation of all accepted parameters.
