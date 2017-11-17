
import Levenshtein

class fuzzy_matcher:
    def score_keywords(self, keywords, target):
        '''
        This method uses a sliding window and the Levenshtein distance to determine if the keyword is found in any substrings of the target. e.g. it helps you recognize that 'paypol' is closely found in 'longpaypalstring'

        :param keywords: List of keywords to monitor for a given domain.
        :param keywords: The potential phishing domain.
        :return:
        '''
        
        score = 0.0

        for keyword in keywords:
            # Find the shorter string
            shorter,longer = (keyword,target) if len(keyword) < len(target) else (target,keyword)

            # Set the window length equal to the shorter string
            window_length = len(shorter)

            # Set the number of times to move the window
            num_iterations = len(longer)-len(shorter)+1

            # Find the Levenshtein distance with the highest ratio (lowest distance)
            for position in range(0, num_iterations):
                window = longer[position:position+window_length]
                result = Levenshtein.ratio(window, shorter)
                if(result > score):
                    score = result
        return score
