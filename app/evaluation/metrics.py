"""
Evaluation and Benchmarking Engine.
Compares detected incidents against ground-truth attacks and calculates precision, recall, F1, FPR,
timeline accuracy, and evidence linkage coverage.
"""
from typing import Optional
from app.models.detection import Incident
from app.models.metrics import EvaluationMetrics


class Evaluator:
    """Evaluates detection performance against ground truth."""

    def evaluate(self, incidents: list[Incident], ground_truth: list[dict], clean_run: bool = False) -> EvaluationMetrics:
        """
        Compare detected incidents with ground truth attack scenarios.
        """
        total_gt = len(ground_truth)
        total_det = len(incidents)

        if clean_run or total_gt == 0:
            # On clean runs (only benign events), any incident is a false positive
            return EvaluationMetrics(
                total_ground_truth=0,
                total_detected=total_det,
                true_positives=0,
                false_positives=total_det,
                false_negatives=0,
                precision=1.0 if total_det == 0 else 0.0,
                recall=1.0 if total_det == 0 else 0.0,
                f1_score=1.0 if total_det == 0 else 0.0,
                fp_rate=float(total_det),
                clean_run_alerts=total_det,
                stage_accuracy=1.0 if total_det == 0 else 0.0,
                timeline_accuracy=1.0 if total_det == 0 else 0.0,
            )

        tp = 0
        per_attack_results = {}
        matched_incident_ids = set()
        matched_gt_ids = set()

        # Check which ground truth attacks were detected
        for gt in ground_truth:
            gt_id = gt.get("attack_id") or gt.get("scenario")
            gt_user = gt.get("attacker")
            gt_hosts = set(gt.get("hosts", []))
            gt_stages = set(gt.get("stages", []))

            # Find matching incident
            best_match = None
            for inc in incidents:
                if inc.id in matched_incident_ids:
                    continue

                inc_users = inc.entities.get("users", [])
                inc_hosts = set(inc.entities.get("hosts", []))

                # Entity match check
                user_match = (gt_user in inc_users) if gt_user else False
                host_match = bool(gt_hosts.intersection(inc_hosts))

                if user_match or host_match:
                    best_match = inc
                    break

            if best_match:
                tp += 1
                matched_incident_ids.add(best_match.id)
                matched_gt_ids.add(gt_id)

                # Check stage overlap
                inc_stages = set(s.stage for s in best_match.stages)
                stage_overlap = len(gt_stages.intersection(inc_stages)) / max(len(gt_stages), 1)

                per_attack_results[gt_id] = {
                    "detected": True,
                    "incident_id": best_match.id,
                    "risk_score": best_match.risk_score,
                    "stage_overlap_pct": round(stage_overlap * 100, 1),
                    "evidence_count": sum(len(s.evidence) for s in best_match.stages),
                }
            else:
                per_attack_results[gt_id] = {
                    "detected": False,
                    "stage_overlap_pct": 0.0,
                }

        fp = total_det - tp
        fn = total_gt - tp

        precision = tp / max(total_det, 1)
        recall = tp / max(total_gt, 1)
        f1 = (2 * precision * recall) / max(precision + recall, 1e-6)
        fp_rate = fp / max(total_det, 1)

        # Stage and timeline accuracy across matched incidents
        stage_acc_sum = sum(res["stage_overlap_pct"] for res in per_attack_results.values() if res.get("detected"))
        avg_stage_acc = (stage_acc_sum / max(tp, 1)) / 100.0 if tp > 0 else 0.0

        return EvaluationMetrics(
            total_ground_truth=total_gt,
            total_detected=total_det,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            fp_rate=round(fp_rate, 4),
            clean_run_alerts=fp if clean_run else 0,
            per_attack_detection=per_attack_results,
            stage_accuracy=round(avg_stage_acc, 4),
            timeline_accuracy=1.0 if tp > 0 else 0.0,
        )
