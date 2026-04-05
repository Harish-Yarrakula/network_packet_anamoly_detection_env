"""
Inference Script Example
===================================
MANDATORY
- Before submitting, ensure the following variables are defined in your environment configuration:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.
    LOCAL_IMAGE_NAME The name of the local image to use for the environment if you are using from_docker_image()
                     method

- Defaults are set only for API_BASE_URL and MODEL_NAME 
    (and should reflect your active inference setup):
    API_BASE_URL = os.getenv("API_BASE_URL", "<your-active-endpoint>")
    MODEL_NAME = os.getenv("MODEL_NAME", "<your-active-model>")
    
- The inference script must be named `inference.py` and placed in the root directory of the project
- Participants must use OpenAI Client for all LLM calls using above variables

STDOUT FORMAT
- The script must emit exactly three line types to stdout, in this order:

    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>

  Rules:
    - One [START] line at episode begin.
    - One [STEP] line per step, immediately after env.step() returns.
    - One [END] line after env.close(), always emitted (even on exception).
    - reward and rewards are formatted to 2 decimal places.
    - done and success are lowercase booleans: true or false.
    - error is the raw last_action_error string, or null if none.
    - All fields on a single line with no newlines within a line.
    - Each tasks should return score in [0, 1]

  Example:
    [START] task=click-test env=miniwob model=Qwen3-VL-30B
    [STEP] step=1 action=click('123') reward=0.00 done=false error=null
    [STEP] step=2 action=fill('456','text') reward=0.00 done=false error=null
    [STEP] step=3 action=click('789') reward=1.00 done=true error=null
    [END] success=true steps=3 score=1.00 rewards=0.00,0.00,1.00
"""

import asyncio
import os
import json
from typing import List, Optional

from dotenv import load_dotenv
from openai import OpenAI

from packet_generator import PacketGenerator
from graders import Task1Grader, Task2Grader, Task3Grader

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# Environment configuration - OpenAI Client for both OpenAI and HuggingFace
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
HF_TOKEN = os.getenv("HF_TOKEN")

# Determine which API to use
if OPENAI_API_KEY:
    API_KEY = OPENAI_API_KEY
    MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")
    API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
else:
    API_KEY = HF_TOKEN
    MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
    API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")

BENCHMARK = "network-packet-anomaly-detection"
MAX_STEPS = 8
TEMPERATURE = 0.7
MAX_TOKENS = 150
SUCCESS_SCORE_THRESHOLD = 0.1  # normalized score in [0, 1]

# Max possible reward: each token contributes 0.1, across all steps
_MAX_REWARD_PER_STEP = MAX_TOKENS * 0.1
MAX_TOTAL_REWARD = MAX_STEPS * _MAX_REWARD_PER_STEP

# Task configuration
TEMPERATURE = 0.3
MAX_TOKENS = 50
SUCCESS_SCORE_THRESHOLD = 0.68

SYSTEM_PROMPT = """You are a network security AI trained via reinforcement learning to detect network anomalies.
Classify each network packet as either NORMAL or ANOMALY based on the features provided.
Respond with only: CLASSIFICATION:confidence
Example: NORMAL:0.95 or ANOMALY:0.87"""


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)


async def main() -> None:
    packet_gen = PacketGenerator()
    graders = [Task1Grader(), Task2Grader(), Task3Grader()]
    generators = [packet_gen.generate_task1_stream, packet_gen.generate_task2_stream, packet_gen.generate_task3_stream]
    
    print("="*70)
    print("Network Packet Anomaly Detection - RL Training")
    print(f"Model: {MODEL_NAME}")
    print(f"API Endpoint: {API_BASE_URL}")
    print("="*70)
    print()
    
    for task_idx, (grader, gen_func) in enumerate(zip(graders, generators), 1):
        task_name = f"task_{task_idx}"
        print(f"[RUN] Starting Task {task_idx}...")
        log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)
        
        try:
            packets = gen_func()
            rewards = []
            
            for step, packet in enumerate(packets, 1):
                try:
                    user_prompt = f"Classify this network packet:\n{json.dumps(packet.to_features_dict())}"
                    
                    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
                    completion = client.chat.completions.create(
                        model=MODEL_NAME,
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_prompt},
                        ],
                        temperature=TEMPERATURE,
                        max_tokens=MAX_TOKENS,
                    )
                    classification_text = completion.choices[0].message.content.strip()
                    
                    result = grader.grade(packet, classification_text)
                    reward = 1.0 * result.confidence if result.correct else -0.5 * result.confidence
                    rewards.append(reward)
                    
                    log_step(step=step, action=classification_text, reward=reward, done=False, error=None)
                    
                except Exception as e:
                    log_step(step=step, action="error", reward=0.0, done=False, error=str(e))
            
            score = sum(rewards) / len(rewards) if rewards else 0.0
            score = min(max(score, 0.0), 1.0)
            success = score >= SUCCESS_SCORE_THRESHOLD
            log_end(success=success, steps=len(packets), score=score, rewards=rewards)
            print(f"[RESULT] Task {task_idx}: Score={score:.4f}, Success={success}")
            print()
            
        except Exception as e:
            log_end(success=False, steps=0, score=0.0, rewards=[])
    
    print("="*70)
    print("TRAINING SUMMARY")
    print("="*70)


if __name__ == "__main__":
    asyncio.run(main())