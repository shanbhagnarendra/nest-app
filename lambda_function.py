import json
import boto3
import urllib.request
import urllib.parse
import urllib.error
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        
        # Check if this is a test event
        if event.get('source') == 'aws.events' or 'detail-type' in event:
            return {
                'statusCode': 200,
                'body': json.dumps('Test event received successfully')
            }
            
        # Check if body exists in the event
        if 'body' in event:
            try:
                payload = json.loads(event['body'])
            except json.JSONDecodeError:
                payload = event['body']  # In case body is already a dict
        else:
            # For direct invocation or testing
            payload = event
            
        logger.info(f"Payload: {json.dumps(payload)}")
        
        # Check if this is a GitHub webhook ping event
        github_event = None
        if 'headers' in event:
            github_event = event['headers'].get('X-GitHub-Event') or event['headers'].get('x-github-event')
            
        if github_event == 'ping':
            return {
                'statusCode': 200,
                'body': json.dumps('GitHub webhook ping received successfully')
            }
            
        # Only process pull_request events with 'opened' or 'synchronize' action
        if github_event == 'pull_request':
            if payload.get('action') not in ['opened', 'synchronize']:
                return {
                    'statusCode': 200,
                    'body': json.dumps(f'Ignoring pull_request event with action: {payload.get("action")}')
                }
        
        # Check if this is a valid pull request event
        if not all(key in payload for key in ['repository', 'pull_request']):
            return {
                'statusCode': 200,
                'body': json.dumps('Event received but not a valid pull request event')
            }
        
        # Extract relevant information from the payload
        repo_name = payload['repository']['full_name']
        pr_number = payload['pull_request']['number']
        pr_diff_url = payload['pull_request']['diff_url']
        
        logger.info(f"Processing PR #{pr_number} from {repo_name}")
        logger.info(f"Diff URL: {pr_diff_url}")
        
        # Get the diff content using urllib
        try:
            with urllib.request.urlopen(pr_diff_url) as response:
                diff_content = response.read().decode('utf-8')
            logger.info(f"Successfully retrieved diff content (length: {len(diff_content)})")
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP Error when fetching diff: {e.code} - {e.reason}")
            return {
                'statusCode': 200,
                'body': json.dumps(f'Error fetching PR diff: {e.code} {e.reason}')
            }
        
        # Use Amazon Bedrock to analyze the code
        try:
            bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')
            logger.info("Calling Amazon Bedrock for code review")
            
            # Claude v2 model
            response = bedrock.invoke_model(
                modelId='anthropic.claude-v2',
                body=json.dumps({
                    "prompt": f"\n\nHuman: You are a helpful code reviewer. Please review the following code diff and provide constructive feedback. Focus on potential bugs, security issues, and suggestions for improvement. Be specific and concise.\n\nDiff:\n{diff_content}\n\nAssistant:",
                    "max_tokens_to_sample": 1000,
                    "temperature": 0.5,
                    "top_p": 0.9
                })
            )
            
            response_body = json.loads(response['body'].read())
            review_comment = response_body['completion']
            logger.info("Successfully generated review comment")
            
        except Exception as e:
            logger.error(f"Error calling Bedrock: {str(e)}")
            return {
                'statusCode': 200,
                'body': json.dumps(f'Error generating review: {str(e)}')
            }
        
        # Post the review comment to GitHub using urllib
        github_token = ''; 
        review_url = f'https://api.github.com/repos/{repo_name}/pulls/{pr_number}/reviews'
        review_data = json.dumps({
            'body': review_comment,
            'event': 'COMMENT'
        }).encode('utf-8')
        
        logger.info(f"Posting review to GitHub URL: {review_url}")
        
        try:
            req = urllib.request.Request(review_url, data=review_data, method='POST')
            req.add_header('Authorization', f'token {github_token}')
            req.add_header('Accept', 'application/vnd.github.v3+json')
            req.add_header('Content-Type', 'application/json')
            
            with urllib.request.urlopen(req) as response:
                response_body = response.read().decode('utf-8')
            logger.info("Successfully posted review to GitHub")
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP Error when posting review: {e.code} - {e.reason}")
            if e.code == 404:
                logger.error("This could indicate an invalid repository name, PR number, or expired token")
            return {
                'statusCode': 200,
                'body': json.dumps(f'Error posting review to GitHub: {e.code} {e.reason}')
            }
        
        return {
            'statusCode': 200,
            'body': json.dumps('Code review completed successfully')
        }
        
    except KeyError as e:
        logger.error(f"KeyError: {str(e)}")
        return {
            'statusCode': 200,
            'body': json.dumps(f'Missing required field: {str(e)}')
        }
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return {
            'statusCode': 200,
            'body': json.dumps(f'Error processing webhook: {str(e)}')
        }