namespace VoiceDetection.Dto
{
    public class AudioAnalysisHistoryDto
    {
        public string AudioFilePath { get; set; }
        public double MatchPercentage { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
