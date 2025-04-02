import logging
from typing import List
from queue import Queue, Empty
import threading
import time

from DrissionPage.errors import StorageError, PageDisconnectedError

from .instance import Instance

class InstancePool:
    def __init__(self, size: int, timeout: int = 120, **kw):
        self.size = size
        self.timeout = timeout
        self.kw = kw
        self.instances: List[Instance] = []
        self.available_instances = Queue()
        self.active_tasks = {}
        self.lock = threading.Lock()
        self.timeout_monitor = threading.Thread(target=self.monitor_timeouts, daemon=True)
        self.timeout_monitor.start()

    def run_task(self, task: dict):
        instance = self.get_instance()
        with self.lock:
            self.active_tasks[instance] = time.time()
        try:
            return instance.task_main(task, self.timeout)
        finally:
            self.return_instance(instance)

    def init_instances(self):
        for _ in range(self.size):
            instance = Instance(**self.kw)
            instance.start()
            self.instances.append(instance)
            self.available_instances.put(instance)

    def get_instance(self) -> Instance:
        return self.available_instances.get()

    def return_instance(self, instance: Instance):
        # First remove from active tasks with lock
        with self.lock:
            if instance in self.active_tasks:
                del self.active_tasks[instance]
        
        # Clean browser data without lock
        try:
            instance.driver.set.cookies.clear()
            instance.driver.clear_cache()
            for k in instance.driver.local_storage():
                instance.driver.set.local_storage(k, False)
            for k in instance.driver.session_storage():
                instance.driver.set.session_storage(k, False)
        except (StorageError, PageDisconnectedError, AttributeError):
            pass

        # Put instance back to queue without lock
        self.available_instances.put(instance)

    def stop(self):
        for instance in self.instances:
            instance.stop()

    def monitor_timeouts(self):
        while True:
            time.sleep(1)
            # Collect timed out instances without holding the lock for too long
            timed_out_instances = []
            with self.lock:
                current_time = time.time()
                for instance, start_time in self.active_tasks.items():
                    if current_time - start_time > self.timeout * 2:
                        timed_out_instances.append(instance)
            
            # Handle timeouts outside the lock
            for instance in timed_out_instances:
                self.handle_timeout(instance)

    def handle_timeout(self, instance: Instance):
        logging.warning(f"Task abnormal timeout detected, restarting instance")
        try:
            new_instance = Instance(**self.kw)
            new_instance.start()

            # Minimize lock holding time
            with self.lock:
                # Replace old instance in instances list
                idx = self.instances.index(instance)
                self.instances[idx] = new_instance
                # Remove from active tasks
                if instance in self.active_tasks:
                    del self.active_tasks[instance]

            # Stop old instance after releasing lock
            instance.stop()

            # Handle queue replacement without holding the main lock
            self._replace_instance_in_queue(instance, new_instance)

        except Exception as e:
            logging.error(f"Error handling timeout: {str(e)}")

    def _replace_instance_in_queue(self, old_instance: Instance, new_instance: Instance):
        temp_instances = []
        # Get all instances from queue
        while True:
            try:
                inst = self.available_instances.get_nowait()
                if inst != old_instance:
                    temp_instances.append(inst)
            except Empty:
                break

        # Put back all valid instances and the new one
        for inst in temp_instances:
            self.available_instances.put(inst)
        self.available_instances.put(new_instance)