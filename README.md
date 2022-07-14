<h1>Prerequisites before deploying to AWS Lambda</h1>
<ol>
  <li>Python 3.8 and above</li>
  <li>Pip</li>
  <li>pipenv</li>
  <li>clone this project</li>
  <li>navigate to project folder and run '$pipenv shell' (make sure to use the correct pipenv python version!)</li>
  <li>next, '$ pipenv install'</li>
</ol>

<p>Once the package has been installed we can move on to the next step</p>

<h1>AWS prerequisite (Make sure you have an account!)</h1>
<h3>AWS RDS</h3>
<ol>
  <li>Create a MySQL DB instance in AWS RDS (t2.micro is more than enough)</li>
  <li>Enter any instance identifier</li>
  <li>Enter the Database username and password (make sure to remember this!)</li>
  <li>Leave everything as default, make sure to set the DB VPC to default for convenience</li>
  <li>Next, click the <b>Additional Configuration</b> dropdown, enter an initial database name <b>(remember this as well!)</b></li>
  <li>Leave everything as default and create the database!</li>
  <li>Next, navigate to <b>'Security Groups'</b> under EC2 service and add an inbound rule for MySQL</li>
  <li>Just allow every source for now (0.0.0.0) for convenience, then save the rule!</li>
</ol>
<h3>AWS S3</h3>
<ol>
  <li>Create a S3 Bucket with any name</li>
  <li>Allow public access and enable website hosting.</li>
  <li>Under the permission tab, add the following policy to bucket permission (change [your-bucket-name-here] to your bucket name</li>
  <code>
    {
      "Version":"2012-10-17",
      "Statement":[{
      "Sid":"PublicReadGetObject",
            "Effect":"Allow",
        "Principal": "*",
          "Action":["s3:GetObject"],
          "Resource":["arn:aws:s3:::[your-bucket-name-here]/*"
          ]
        }
      ]
    }
  </code>
</ol>

<h1>Database Migration</h1>
<p>Currently looking for a better solution...</p>
<ol>
  <li>Open the <code>ddac_project</code> folder, within the <code>settings.py</code> file, append the database credentials to the <code>DATABASES</code> variable</li>
  <ul>
    <ol><code>NAME</code> - the database name</ol>
    <ol><code>USER</code> - the database username</ol>
    <ol><code>PASSWORD</code> - the database password</ol>
    <ol><code>HOST</code> - the database hostname (url)</ol>
    <ol><code>PORT</code> - the database port (usually 3306)</ol>
  </ul>

  <li>After that, navigate to the project folder in the terminal and run <code>pipenv shell</code> (make sure to be in root directory)</li>
  <li>Run the following: <code>python manage.py migrate</code></li>
  <li>Create a super user now <code>python manage.py createsuperuser</code></p>
  <li>Once successful, change the database credentials to the following:</li>
  <ul>
    <ol><code>NAME</code> - <code>os.environ['NAME']</code></ol>
    <ol><code>USER</code> - <code>os.environ['USER']</code></ol>
    <ol><code>PASSWORD</code> - <code>os.environ['PASSWORD']</code></ol>
    <ol><code>HOST</code> - <code>os.environ['HOST']</code></ol>
    <ol><code>PORT</code> - <code>os.environ['PORT']</code></ol>
  </ul>
  <li>Once complete, we can start deployment with Zappa</li>
</ol>

<h1>Deployment</h1>
<ol>
  <li>delete the <code>zappa_settings.json</code> file if exists</li>
  <li>back in the terminal, run the following <code>zappa init</code>, and follow the wizard</li>
  <li>once the wizard is compelete, run the following <code>zappa deploy dev</code></li>
  <li>don't worry about 500/502 error shown by zappa for now, we will fix it</li>
  <li>Before fixing the error, grab the API Gateway URL (ex. ******.execute-api.us-east-1.amazonaws.com), append the URL to <code>settings.py</code> <code>ALLOWED_HOSTS</code>     </li>
  <li>Next, visit Lambda service in the AWS Dashboard, and select the project function.</li>
  <li>Under the configuration tab -> environment variables, add the respective environment variables (ex. key: NAME, value: DATABASE_NAME)</li>
  <li>once that is settled, go back to the terminal and update the deployment using the following <code>zappa update [zappa-name]</code></li>
</ol>

<h1>Where is the frontend?</h1>
<p>too lazy to write script, so...</p>
<p>copy the whole content within the frontend folder and just dump it to your S3 bucket</p>
<p>one last thing, go to <code>index.js</code> file, change the <code>API_URL</code> to your API Gateway url</p>
<p>finally, just visit your s3 website hosting url and done.</p>
