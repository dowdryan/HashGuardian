from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
from peft import PeftModel

BASE = "Qwen/Qwen3-4B-Base"
ADAPTER = "dowdryan/adaption_fim_event_classification"

base = AutoModelForCausalLM.from_pretrained(BASE, dtype="auto", device_map="auto")
# Merge the LoRA weights into the base for faster inference
model = PeftModel.from_pretrained(base, ADAPTER).merge_and_unload()
model.eval()
tokenizer = AutoTokenizer.from_pretrained(BASE)

pipe = pipeline("text-generation", model=model, tokenizer=tokenizer)

messages = [{"role": "user", "content": "Hello!"}]
out = pipe(messages, max_new_tokens=512)
print(out[0]["generated_text"][-1]["content"])