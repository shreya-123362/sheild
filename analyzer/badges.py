"""
badges.py
Simple milestone tracking based on total number of cases analyzed.
Subtle recognition, not a full gamification system - just small
badges that unlock at certain scan counts.
"""

BADGE_MILESTONES = [
    (1, "First Case", "Analyzed your first email"),
    (10, "Case Files", "Analyzed 10 emails"),
    (25, "Seasoned Analyst", "Analyzed 25 emails"),
    (50, "Threat Hunter", "Analyzed 50 emails"),
]


def get_earned_badges(total_cases):
    """
    Returns the list of badges earned so far, based on total case count.
    A badge counts as 'earned' once you've hit or passed its threshold.
    """
    earned = []
    for threshold, name, description in BADGE_MILESTONES:
        if total_cases >= threshold:
            earned.append({
                "name": name,
                "description": description,
                "threshold": threshold,
            })
    return earned


def get_next_badge(total_cases):
    """
    Returns the next badge not yet earned, plus how many more scans
    are needed to reach it. Returns None if all badges are earned.
    """
    for threshold, name, description in BADGE_MILESTONES:
        if total_cases < threshold:
            return {
                "name": name,
                "description": description,
                "threshold": threshold,
                "remaining": threshold - total_cases,
            }
    return None
