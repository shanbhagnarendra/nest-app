            # Use Amazon Bedrock to analyze the code
            try:
                bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')
                logger.info("Calling Amazon Bedrock for code review")
                
                # Use Claude v2 model
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
